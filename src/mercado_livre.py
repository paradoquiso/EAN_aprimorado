import requests
import json
import time
import re
import urllib.parse
import logging
import os

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Credenciais e Configurações (Ler das variáveis de ambiente)
CLIENT_ID = os.environ.get("ML_CLIENT_ID")
CLIENT_SECRET = os.environ.get("ML_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("ML_REDIRECT_URI") # Essencial para o fluxo authorization_code

# URL base da API e de Autenticação (Brasil)
AUTH_BASE_URL = "https://auth.mercadolivre.com.br"
API_BASE_URL = "https://api.mercadolibre.com"

def get_authorization_url():
    """Gera a URL de autorização do Mercado Livre para o usuário."""
    if not CLIENT_ID or not REDIRECT_URI:
        logger.error("ML_CLIENT_ID ou ML_REDIRECT_URI não configurados nas variáveis de ambiente.")
        return None
    
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI
        # "state": "opcional_para_seguranca" # Pode adicionar um state se necessário
    }
    auth_url = f"{AUTH_BASE_URL}/authorization?{urllib.parse.urlencode(params)}"
    logger.info(f"Gerando URL de autorização: {auth_url}")
    return auth_url

def exchange_code_for_token(code):
    """Troca o código de autorização por um access token e refresh token."""
    if not CLIENT_ID or not CLIENT_SECRET or not REDIRECT_URI:
        logger.error("Credenciais ML (ID, Secret, Redirect URI) não configuradas.")
        return None

    url = f"{API_BASE_URL}/oauth/token"
    payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "redirect_uri": REDIRECT_URI
    }
    headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}

    try:
        logger.info(f"Trocando código por token. URL: {url}")
        response = requests.post(url, data=payload, headers=headers, timeout=20)
        response.raise_for_status() # Lança exceção para erros HTTP (4xx ou 5xx)
        
        token_data = response.json()
        logger.info("Token obtido com sucesso via authorization_code.")
        # Adiciona o tempo de expiração calculado
        token_data['expires_at'] = time.time() + token_data.get('expires_in', 0)
        return token_data

    except requests.exceptions.RequestException as e:
        logger.error(f"Erro ao trocar código por token: {e}. Resposta: {e.response.text if e.response else 'N/A'}")
        return None
    except Exception as e:
        logger.error(f"Erro inesperado ao trocar código por token: {str(e)}")
        return None

def refresh_access_token(refresh_token):
    """Usa o refresh token para obter um novo access token."""
    if not CLIENT_ID or not CLIENT_SECRET:
        logger.error("Credenciais ML (ID, Secret) não configuradas para refresh.")
        return None

    url = f"{API_BASE_URL}/oauth/token"
    payload = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token
    }
    headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}

    try:
        logger.info(f"Atualizando token com refresh_token. URL: {url}")
        response = requests.post(url, data=payload, headers=headers, timeout=20)
        response.raise_for_status()
        
        token_data = response.json()
        logger.info("Token atualizado com sucesso via refresh_token.")
        # Adiciona o tempo de expiração calculado
        token_data['expires_at'] = time.time() + token_data.get('expires_in', 0)
        return token_data

    except requests.exceptions.RequestException as e:
        logger.error(f"Erro ao atualizar token: {e}. Resposta: {e.response.text if e.response else 'N/A'}")
        return None
    except Exception as e:
        logger.error(f"Erro inesperado ao atualizar token: {str(e)}")
        return None

def fallback_busca_produto(ean, message="Não foi possível buscar informações do produto online."):
    """ Retorna uma estrutura padrão em caso de falha na busca. """
    logger.warning(f"Fallback acionado para EAN: {ean}. Motivo: {message}")
    return {
        "success": False,
        "data": {
            "nome": f"Produto {ean} (não encontrado)",
            "cor": "",
            "voltagem": "",
            "modelo": "",
            "ean": ean,
            "url": "",
            "preco_medio": None
        },
        "message": message,
        "source": "fallback"
    }

def buscar_produto_por_ean(ean, access_token):
    """
    Busca informações de um produto pelo código EAN utilizando a API do Mercado Livre
    com um access_token obtido via authorization_code.
    """
    if not access_token:
        return fallback_busca_produto(ean, "Access token inválido ou ausente.")

    try:
        logger.info(f"Iniciando busca para o EAN: {ean} com token fornecido.")
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "User-Agent": "EANSearchApp/1.0 (AuthCodeFlow)" # User agent customizado
        }
        
        # Busca usando o endpoint sites/MLB/search (focado em anúncios para obter preço)
        logger.info(f"Buscando anúncios com EAN {ean} via sites/MLB/search")
        encoded_ean = urllib.parse.quote(ean)
        # Buscar por EAN e limitar a quantidade para cálculo de preço
        url_search = f"{API_BASE_URL}/sites/MLB/search?q={encoded_ean}&limit=10"
        
        try:
            response_search = requests.get(url_search, headers=headers, timeout=15)
            
            # Tratamento específico para 401 (Token inválido/expirado) antes de raise_for_status geral
            if response_search.status_code == 401:
                 logger.error(f"Erro de autenticação (401) na API sites/search. Token inválido ou expirado.")
                 # Não usar fallback aqui, deixar o main.py tratar a necessidade de refresh/re-auth
                 return {"success": False, "error": "invalid_token", "message": "Token de acesso inválido ou expirado.", "status_code": 401}
            
            # Lança exceção para outros erros HTTP (4xx, 5xx) que não sejam 401
            response_search.raise_for_status()

            # Se chegou aqui, status code é 2xx
            data_search = response_search.json()
            results_search = data_search.get("results", [])
            logger.info(f"Endpoint sites/MLB/search retornou {len(results_search)} anúncios")

            if results_search:
                produto_encontrado = None
                precos = []
                
                # Lógica para encontrar o produto e calcular preço médio (mantida do original)
                for item in results_search:
                    atributos_item = item.get("attributes", [])
                    ean_matches = False
                    for attr in atributos_item:
                        attr_id = attr.get("id", "").upper()
                        attr_value = str(attr.get("value_name", ""))
                        if attr_id in ["EAN", "GTIN"] and attr_value == ean:
                            ean_matches = True
                            break
                    
                    item_price = item.get("price")
                    if item_price is not None:
                         try:
                             precos.append(float(item_price))
                         except (ValueError, TypeError):
                             logger.warning(f"Não foi possível converter preço '{item_price}' para float no item ID {item.get('id')}")

                    if ean_matches and not produto_encontrado:
                        produto_encontrado = item
                        logger.info(f"Anúncio com EAN correspondente encontrado: ID {item.get('id')}")
                
                if not produto_encontrado and results_search:
                    produto_encontrado = results_search[0]
                    logger.info("Nenhum anúncio com EAN correspondente. Usando o primeiro resultado como referência.")
                elif not produto_encontrado:
                     logger.warning(f"Nenhum resultado encontrado na busca por EAN {ean}.")
                     return fallback_busca_produto(ean, "Nenhum anúncio encontrado para o EAN.")

                preco_medio = None
                if precos:
                    preco_medio = round(sum(precos) / len(precos), 2)
                    logger.info(f"Preço médio calculado: R$ {preco_medio:.2f} (de {len(precos)} anúncios)")
                else:
                    logger.warning(f"Nenhum preço válido encontrado nos anúncios para EAN {ean}.")

                nome_base = produto_encontrado.get("title", f"Produto {ean}")
                permalink = produto_encontrado.get("permalink", "")
                atributos = produto_encontrado.get("attributes", [])
                cor, voltagem, modelo, marca = "", "", "", ""
                
                for attr in atributos:
                    attr_id = attr.get("id", "").upper()
                    attr_name = attr.get("name", "").upper()
                    attr_value = attr.get("value_name", "")
                    if not attr_value: continue
                    if attr_id == "COLOR" or "COR" in attr_name: cor = attr_value
                    elif attr_id == "VOLTAGE" or "VOLTAGEM" in attr_name: voltagem = attr_value
                    elif attr_id == "MODEL" or "MODELO" in attr_name: modelo = attr_value
                    elif attr_id == "BRAND" or "MARCA" in attr_name: marca = attr_value
                
                # Limpeza básica do nome (mantida do original)
                nome_limpo = re.sub(r'\s*-\s*(' + '|'.join(re.escape(v) for v in [cor, voltagem, modelo, marca] if v) + ')', '', nome_base, flags=re.IGNORECASE).strip()
                nome_limpo = re.sub(r'\b(' + '|'.join(re.escape(v) for v in [cor, voltagem, modelo, marca] if v) + ')\b', '', nome_limpo, flags=re.IGNORECASE).strip()
                nome_limpo = ' '.join(nome_limpo.split())
                if not nome_limpo: nome_limpo = nome_base # Fallback se a limpeza remover tudo

                logger.info(f"Produto encontrado: {nome_limpo}, Cor: {cor}, Voltagem: {voltagem}, Modelo: {modelo}, Preço Médio: {preco_medio}")
                return {
                    "success": True,
                    "data": {
                        "nome": nome_limpo,
                        "cor": cor,
                        "voltagem": voltagem,
                        "modelo": modelo,
                        "ean": ean,
                        "url": permalink,
                        "preco_medio": preco_medio
                    },
                    "message": "Produto encontrado no Mercado Livre.",
                    "source": "mercado_livre_search_authcode"
                }
            else:
                logger.warning(f"Nenhum resultado encontrado na busca por EAN {ean}.")
                return fallback_busca_produto(ean, "Nenhum anúncio encontrado para o EAN.")
        
        except requests.exceptions.Timeout:
            logger.error(f"Timeout ao buscar anúncios para EAN {ean}.")
            return fallback_busca_produto(ean, "Timeout ao conectar com a API do Mercado Livre.")
        except requests.exceptions.RequestException as e:
            # Erros HTTP diferentes de 401 já tratados acima
            logger.error(f"Erro na requisição de busca de anúncios (sites/search): {e}. Resposta: {e.response.text if e.response else 'N/A'}")
            return fallback_busca_produto(ean, f"Erro na API do Mercado Livre: {e.response.status_code if e.response else 'N/A'}")
        except Exception as e:
            logger.error(f"Erro inesperado na lógica de busca de anúncios: {str(e)}")
            return fallback_busca_produto(ean, "Erro interno ao processar busca.")

    except Exception as e:
        logger.exception(f"Erro inesperado geral ao buscar produto por EAN {ean}: {str(e)}")
        return fallback_busca_produto(ean, "Erro inesperado no sistema.")

# Remover o bloco if __name__ == '__main__' que usava client_credentials
