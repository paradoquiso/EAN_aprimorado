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

# Credenciais do Mercado Livre (Considerar mover para variáveis de ambiente)
CLIENT_ID = os.environ.get("ML_CLIENT_ID", "7401826900082952")
CLIENT_SECRET = os.environ.get("ML_CLIENT_SECRET", "AtsQ0fxExmiYTE8eE0bAWi1Q1yOL26Jv")
# AUTH_CODE é temporário e deve ser obtido via fluxo OAuth2. Usar refresh token é mais robusto.
# Para este exemplo, manteremos o código, mas idealmente seria um refresh token.
AUTH_CODE = os.environ.get("ML_AUTH_CODE", "TG-68308070dc6cc300010c309a-2450304038") 
REDIRECT_URI = os.environ.get("ML_REDIRECT_URI", "https://localhost/callback") # Ajustar conforme necessário

def obter_access_token():
    """
    Obtém um token de acesso válido para a API do Mercado Livre.
    Tenta usar um token salvo, senão tenta obter um novo com AUTH_CODE,
    e como último recurso, tenta com client_credentials (menos permissões).
    """
    token_file = "/tmp/ml_access_token.json"
    token_data = None

    # 1. Tentar carregar token salvo e verificar validade
    if os.path.exists(token_file):
        try:
            with open(token_file, "r") as f:
                token_data = json.load(f)
                expires_at = token_data.get("expires_at", 0)
                if time.time() < expires_at - 300: # Margem de 5 minutos
                    logger.info(f"Usando token de acesso existente (válido até {time.ctime(expires_at)})")
                    return token_data.get("access_token")
                else:
                    logger.info("Token salvo expirado ou inválido.")
                    # Tentar usar refresh token se disponível
                    if "refresh_token" in token_data:
                        logger.info("Tentando renovar token com refresh_token.")
                        return refresh_access_token(token_data["refresh_token"])
        except Exception as e:
            logger.error(f"Erro ao ler ou processar token salvo: {str(e)}")
            token_data = None # Resetar token_data em caso de erro

    # 2. Se não há token válido ou refresh falhou, tentar obter novo com AUTH_CODE
    logger.info("Tentando obter novo token com código de autorização (AUTH_CODE).")
    url = "https://api.mercadolibre.com/oauth/token"
    payload_auth = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": AUTH_CODE,
        "redirect_uri": REDIRECT_URI
    }
    headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    
    try:
        response = requests.post(url, data=payload_auth, headers=headers, timeout=15)
        if response.status_code == 200:
            new_token_data = response.json()
            access_token = new_token_data.get("access_token")
            expires_in = new_token_data.get("expires_in", 21600)
            refresh_token = new_token_data.get("refresh_token")
            
            save_token_data({
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_at": time.time() + expires_in,
                "obtained_at": time.time()
            })
            logger.info(f"Token obtido com AUTH_CODE: {access_token[:10]}...")
            return access_token
        else:
            logger.error(f"Erro ao obter token com AUTH_CODE: {response.status_code} - {response.text}")
            # Limpar AUTH_CODE para não tentar novamente com código inválido?
            # global AUTH_CODE
            # AUTH_CODE = None 
    except Exception as e:
        logger.error(f"Exceção ao obter token com AUTH_CODE: {str(e)}")

    # 3. Tentar obter token com client_credentials (menos permissões, pode não funcionar para tudo)
    logger.info("Tentando obter token com client_credentials.")
    payload_client = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }
    try:
        response = requests.post(url, data=payload_client, headers=headers, timeout=15)
        if response.status_code == 200:
            cc_token_data = response.json()
            access_token = cc_token_data.get("access_token")
            expires_in = cc_token_data.get("expires_in", 21600)
            
            # Não salva token client_credentials pois não tem refresh_token
            # save_token_data({
            #     "access_token": access_token,
            #     "expires_at": time.time() + expires_in,
            #     "obtained_at": time.time(),
            #     "grant_type": "client_credentials"
            # })
            logger.info(f"Token obtido com client_credentials: {access_token[:10]}...")
            return access_token
        else:
            logger.error(f"Erro ao obter token com client_credentials: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"Exceção ao obter token com client_credentials: {str(e)}")

    # 4. Falha total
    logger.error("Falha ao obter token de acesso por todos os métodos.")
    return None

def refresh_access_token(refresh_token):
    """ Tenta renovar o token usando o refresh_token. """
    url = "https://api.mercadolibre.com/oauth/token"
    payload = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token
    }
    headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    
    try:
        response = requests.post(url, data=payload, headers=headers, timeout=15)
        if response.status_code == 200:
            new_token_data = response.json()
            access_token = new_token_data.get("access_token")
            expires_in = new_token_data.get("expires_in", 21600)
            new_refresh_token = new_token_data.get("refresh_token", refresh_token) # Reutiliza o antigo se não vier novo
            
            save_token_data({
                "access_token": access_token,
                "refresh_token": new_refresh_token,
                "expires_at": time.time() + expires_in,
                "obtained_at": time.time()
            })
            logger.info(f"Token renovado com sucesso: {access_token[:10]}...")
            return access_token
        else:
            logger.error(f"Erro ao renovar token: {response.status_code} - {response.text}")
            # Se refresh falhar (ex: 400 Bad Request - token inválido), limpar token salvo
            if response.status_code == 400:
                 clear_token_data()
            return None
    except Exception as e:
        logger.error(f"Exceção ao renovar token: {str(e)}")
        return None

def save_token_data(token_data):
    """ Salva os dados do token em um arquivo temporário. """
    token_file = "/tmp/ml_access_token.json"
    try:
        with open(token_file, "w") as f:
            json.dump(token_data, f, indent=2)
        logger.debug(f"Token data saved to {token_file}")
    except Exception as e:
        logger.error(f"Erro ao salvar token no arquivo {token_file}: {str(e)}")

def clear_token_data():
    """ Remove o arquivo de token salvo. """
    token_file = "/tmp/ml_access_token.json"
    if os.path.exists(token_file):
        try:
            os.remove(token_file)
            logger.info(f"Arquivo de token removido: {token_file}")
        except Exception as e:
            logger.error(f"Erro ao remover arquivo de token {token_file}: {str(e)}")

def fallback_busca_produto(ean):
    """ Retorna uma estrutura padrão em caso de falha na busca. """
    logger.warning(f"Fallback acionado para EAN: {ean}")
    return {
        "success": False,
        "data": {
            "nome": f"Produto {ean} (não encontrado)",
            "cor": "",
            "voltagem": "",
            "modelo": "",
            "ean": ean,
            "url": "",
            "preco_medio": None # Incluir campo de preço médio
        },
        "message": "Não foi possível buscar informações do produto online.",
        "source": "fallback"
    }

def buscar_produto_por_ean(ean):
    """
    Busca informações de um produto pelo código EAN utilizando múltiplas estratégias
    de busca na API do Mercado Livre, incluindo cálculo de preço médio.
    """
    try:
        logger.info(f"Iniciando busca para o EAN: {ean}")
        
        access_token = obter_access_token()
        if not access_token:
            logger.error("Não foi possível obter token de acesso. Usando fallback.")
            return fallback_busca_produto(ean)
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "User-Agent": "EANSearchApp/1.0" # User agent customizado
        }
        
        # Estratégia 1: Busca usando o endpoint products/search com product_identifier (focado em catálogo)
        # Este endpoint pode não retornar preço diretamente, mas pode dar info de catálogo
        logger.info(f"Estratégia 1: Buscando catálogo com EAN {ean} via products/search")
        site_id = "MLB"
        status = "active"
        url_prod = f"https://api.mercadolibre.com/products/search?status={status}&site_id={site_id}&product_identifier={ean}"
        
        try:
            response_prod = requests.get(url_prod, headers=headers, timeout=10)
            if response_prod.status_code == 200:
                data_prod = response_prod.json()
                results_prod = data_prod.get("results", [])
                if results_prod:
                    produto_cat = results_prod[0]
                    nome_cat = produto_cat.get("name", "")
                    atributos_cat = produto_cat.get("attributes", [])
                    cor_cat, voltagem_cat, modelo_cat = "", "", ""
                    for attr in atributos_cat:
                        attr_id = attr.get("id", "").upper()
                        attr_value = attr.get("value_name", "")
                        if attr_id == "COLOR" or "COR" in attr_id: cor_cat = attr_value
                        elif attr_id == "VOLTAGE" or "VOLTAGEM" in attr_id: voltagem_cat = attr_value
                        elif attr_id == "MODEL" or "MODELO" in attr_id: modelo_cat = attr_value
                    
                    logger.info(f"Catálogo encontrado via products/search: {nome_cat}")
                    # Guardar info do catálogo para complementar se a busca de anúncios falhar
                    # Não retorna aqui ainda, pois queremos o preço da busca de anúncios
            elif response_prod.status_code == 401:
                logger.error(f"Erro de autenticação (401) na API products/search. Token pode ter expirado.")
                # Tentar obter novo token na próxima chamada
            else:
                 logger.warning(f"API products/search respondeu com status {response_prod.status_code}")
        except Exception as e:
            logger.error(f"Erro na Estratégia 1 (products/search): {str(e)}")

        # Estratégia 2: Busca usando o endpoint sites/MLB/search (focado em anúncios)
        logger.info(f"Estratégia 2: Buscando anúncios com EAN {ean} via sites/MLB/search")
        encoded_ean = urllib.parse.quote(ean)
        # Buscar por EAN e limitar a quantidade para cálculo de preço
        url_search = f"https://api.mercadolibre.com/sites/MLB/search?q={encoded_ean}&limit=10" 
        
        try:
            response_search = requests.get(url_search, headers=headers, timeout=15)
            
            # Salvar resposta para debug
            # with open(f"/tmp/ml_sites_search_{ean}.json", "w") as f:
            #     json.dump(response_search.json() if response_search.status_code == 200 else {"error": response_search.status_code, "text": response_search.text}, f, indent=2)

            if response_search.status_code == 200:
                data_search = response_search.json()
                results_search = data_search.get("results", [])
                logger.info(f"Endpoint sites/MLB/search retornou {len(results_search)} anúncios")

                if results_search:
                    # Encontrar o produto mais relevante (idealmente com EAN correspondente)
                    produto_encontrado = None
                    precos = []
                    
                    for item in results_search:
                        # Verificar se o EAN bate (se disponível nos atributos do anúncio)
                        atributos_item = item.get("attributes", [])
                        ean_matches = False
                        for attr in atributos_item:
                            attr_id = attr.get("id", "").upper()
                            attr_value = str(attr.get("value_name", ""))
                            if attr_id in ["EAN", "GTIN"] and attr_value == ean:
                                ean_matches = True
                                break
                        
                        # Coletar preço se o EAN bate ou se for o primeiro item (como fallback)
                        item_price = item.get("price")
                        if item_price is not None:
                             try:
                                 precos.append(float(item_price))
                             except (ValueError, TypeError):
                                 logger.warning(f"Não foi possível converter preço '{item_price}' para float no item ID {item.get('id')}")

                        # Definir como produto principal se o EAN bateu
                        if ean_matches and not produto_encontrado:
                            produto_encontrado = item
                            logger.info(f"Anúncio com EAN correspondente encontrado: ID {item.get('id')}")
                    
                    # Se nenhum anúncio bateu com EAN, usar o primeiro como referência
                    if not produto_encontrado:
                        produto_encontrado = results_search[0]
                        logger.info("Nenhum anúncio com EAN correspondente. Usando o primeiro resultado como referência.")

                    # Calcular preço médio
                    preco_medio = None
                    if precos:
                        preco_medio = round(sum(precos) / len(precos), 2)
                        logger.info(f"Preço médio calculado: R$ {preco_medio:.2f} (de {len(precos)} anúncios)")
                    else:
                        logger.warning(f"Nenhum preço válido encontrado nos anúncios para EAN {ean}.")

                    # Extrair informações do produto encontrado (priorizar anúncio)
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
                    
                    # Complementar com info do catálogo se faltar no anúncio (opcional)
                    # if not cor and 'cor_cat' in locals() and cor_cat: cor = cor_cat
                    # ... (similar para outros atributos)

                    # Construir nome completo (pode refinar esta lógica)
                    nome_completo = nome_base # Simplificado por agora
                    logger.info(f"Produto encontrado via sites/search: {nome_completo}")

                    return {
                        "success": True,
                        "data": {
                            "nome": nome_completo,
                            "cor": cor,
                            "voltagem": voltagem,
                            "modelo": modelo,
                            "ean": ean,
                            "url": permalink,
                            "preco_medio": preco_medio # Adicionado preço médio
                        },
                        "source": "api_sites_search"
                    }
                else:
                    logger.warning(f"Nenhum anúncio encontrado para EAN {ean} via sites/MLB/search.")

            elif response_search.status_code == 401:
                logger.error(f"Erro de autenticação (401) na API sites/search. Token pode ter expirado.")
            else:
                logger.warning(f"API sites/search respondeu com status {response_search.status_code}")
        
        except Exception as e:
            logger.error(f"Erro na Estratégia 2 (sites/search): {str(e)}")

        # Se chegou aqui, nenhuma estratégia funcionou
        logger.warning(f"Nenhuma estratégia de busca retornou resultados válidos para o EAN {ean}. Usando fallback.")
        return fallback_busca_produto(ean)

    except Exception as e:
        logger.error(f"Erro GERAL ao buscar produto por EAN {ean}: {str(e)}")
        return fallback_busca_produto(ean)

# Exemplo de uso (para teste)
if __name__ == '__main__':
    test_ean = "7891000315678" # Exemplo EAN (Coca-Cola)
    # test_ean = "7896094916675" # Exemplo EAN (Celular)
    # test_ean = "1234567890123" # Exemplo EAN inválido
    
    resultado = buscar_produto_por_ean(test_ean)
    print("\nResultado da busca:")
    print(json.dumps(resultado, indent=2, ensure_ascii=False))

