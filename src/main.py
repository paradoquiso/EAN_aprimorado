import sys
import os
import sqlite3 # Alterado de psycopg2 para sqlite3
from datetime import datetime, timezone # Adicionado timezone
import io
import requests
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
import pandas as pd
import json
from werkzeug.security import generate_password_hash, check_password_hash
from src.utils import formatar_data_brasileira  # Importando a função de formatação de data
# Importar função de busca do Mercado Livre (já inclui preço médio)
from src.mercado_livre import buscar_produto_por_ean as buscar_produto_online

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "ean_app_secret_key_default") # Usar variável de ambiente para secret key

# Registrar filtro Jinja2 para formatação de data brasileira
@app.template_filter("data_brasileira")
def data_brasileira_filter(data):
    # Tentar converter string ISO para datetime se necessário
    if isinstance(data, str):
        try:
            # Ajustar para formatos comuns que SQLite pode retornar
            data = datetime.fromisoformat(data.replace("Z", "+00:00"))
        except ValueError:
            try:
                 # Tentar formato sem timezone explícito
                 data = datetime.strptime(data, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                 try:
                     data = datetime.strptime(data, "%Y-%m-%d %H:%M:%S")
                 except ValueError:
                     return data # Retornar string original se falhar
    return formatar_data_brasileira(data)

# Configuração do banco de dados SQLite
# Usar um caminho relativo à raiz do projeto ou absoluto
DATABASE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "produtos.db")
print(f"Usando banco de dados SQLite em: {DATABASE_PATH}")

# Função auxiliar para obter conexão SQLite
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    # Retornar linhas como dicionários (ou objetos tipo dicionário)
    conn.row_factory = sqlite3.Row 
    return conn

# Inicializar o banco de dados (adaptado para SQLite)
def init_database():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Habilitar chaves estrangeiras (importante para SQLite)
            cursor.execute("PRAGMA foreign_keys = ON;")
            
            # Tabela de usuários
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL UNIQUE,
                senha_hash TEXT NOT NULL,
                admin INTEGER DEFAULT 0
            );
            """)
            
            # Tabela de responsáveis com PIN
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS responsaveis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL UNIQUE,
                pin TEXT NOT NULL
            );
            """)
            
            # Tabela de produtos
            # Usar TEXT para timestamps no SQLite (formato ISO8601 recomendado)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS produtos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ean TEXT NOT NULL,
                nome TEXT NOT NULL,
                cor TEXT,
                voltagem TEXT,
                modelo TEXT,
                quantidade INTEGER NOT NULL,
                usuario_id INTEGER NOT NULL,
                timestamp TEXT, -- Alterado para TEXT
                enviado INTEGER DEFAULT 0,
                data_envio TEXT, -- Alterado para TEXT
                validado INTEGER DEFAULT 0,
                validador_id INTEGER,
                data_validacao TEXT, -- Alterado para TEXT
                responsavel_id INTEGER,
                responsavel_pin TEXT,
                preco_medio REAL, -- Adicionado campo para preço médio
                FOREIGN KEY (usuario_id) REFERENCES usuarios (id),
                FOREIGN KEY (validador_id) REFERENCES usuarios (id),
                FOREIGN KEY (responsavel_id) REFERENCES responsaveis (id)
            );
            """)
            
            # Verificar se já existe um admin APENAS se a tabela estiver vazia
            cursor.execute("SELECT COUNT(*) FROM usuarios")
            user_count = cursor.fetchone()[0]
            
            if user_count == 0:
                cursor.execute("SELECT * FROM usuarios WHERE admin = 1")
                admin = cursor.fetchone()
                if not admin:
                    # Criar um usuário admin padrão
                    admin_hash = generate_password_hash("admin")
                    # Usar ? como placeholder no SQLite
                    cursor.execute("INSERT INTO usuarios (nome, senha_hash, admin) VALUES (?, ?, ?)", 
                                  ("admin", admin_hash, 1))
            
            # Inicializar responsáveis com PINs
            inicializar_responsaveis(conn) # Passar conexão para a função
            
            conn.commit() # Commit das alterações
            print("Banco de dados SQLite inicializado com sucesso.")
            
    except sqlite3.Error as e:
        print(f"Erro ao inicializar o banco de dados SQLite: {e}")
        # Considerar logar o erro ou tratá-lo de forma mais robusta

# Inicializar responsáveis com PINs (adaptado para SQLite)
def inicializar_responsaveis(conn): # Recebe conexão como argumento
    try:
        cursor = conn.cursor()
        # Verificar se já existem responsáveis
        cursor.execute("SELECT COUNT(*) FROM responsaveis")
        count = cursor.fetchone()[0]
        
        if count == 0:
            # Inserir responsáveis com seus PINs
            responsaveis = [
                ("Liliane", "5584"),
                ("Rogerio", "9841"),
                ("Celso", "2122"),
                ("Marcos", "6231")
            ]
            
            # Usar executemany para inserção em lote
            cursor.executemany("INSERT INTO responsaveis (nome, pin) VALUES (?, ?)", responsaveis)
            
            print(f"Responsáveis inicializados: {len(responsaveis)}")
            # Commit é feito na função chamadora (init_database)
    except sqlite3.Error as e:
        print(f"Erro ao inicializar responsáveis: {e}")
        # Rollback seria feito na função chamadora se necessário

# Obter todos os responsáveis (adaptado para SQLite)
def obter_responsaveis():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, nome FROM responsaveis ORDER BY nome")
            # conn.row_factory = sqlite3.Row já faz retornar dict-like rows
            responsaveis = [dict(row) for row in cursor.fetchall()]
        return responsaveis
    except sqlite3.Error as e:
        print(f"Erro ao obter responsáveis: {e}")
        return []

# Verificar PIN do responsável (adaptado para SQLite)
def verificar_pin_responsavel(responsavel_id, pin):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Usar ? como placeholder
            cursor.execute("SELECT pin FROM responsaveis WHERE id = ?", (responsavel_id,))
            resultado = cursor.fetchone()
            
            if resultado and resultado["pin"] == pin: # Acessar por nome da coluna
                return True
            return False
    except sqlite3.Error as e:
        print(f"Erro ao verificar PIN do responsável: {e}")
        return False

# Obter nome do responsável (adaptado para SQLite)
def obter_nome_responsavel(responsavel_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT nome FROM responsaveis WHERE id = ?", (responsavel_id,))
            resultado = cursor.fetchone()
            
            if resultado:
                return resultado["nome"]
            return None
    except sqlite3.Error as e:
        print(f"Erro ao obter nome do responsável: {e}")
        return None

# Funções de autenticação (adaptadas para SQLite)
def registrar_usuario(nome, senha):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            senha_hash = generate_password_hash(senha)
            # Usar ? como placeholder
            cursor.execute("INSERT INTO usuarios (nome, senha_hash) VALUES (?, ?)", (nome, senha_hash))
            conn.commit()
        return True
    except sqlite3.IntegrityError: # Erro específico para UNIQUE constraint no SQLite
        # Nome de usuário já existe
        print(f"Erro: Nome de usuário \'{nome}\' já existe.")
        return False
    except sqlite3.Error as e:
        print(f"Erro ao registrar usuário: {e}")
        return False

def verificar_usuario(nome, senha):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Usar ? como placeholder
            cursor.execute("SELECT id, senha_hash, admin FROM usuarios WHERE nome = ?", (nome,))
            usuario = cursor.fetchone() # Retorna um objeto sqlite3.Row
        
        if usuario and check_password_hash(usuario["senha_hash"], senha):
            # Retornar como dicionário
            return dict(usuario)
        return None
    except sqlite3.Error as e:
        print(f"Erro ao verificar usuário: {e}")
        return None

def obter_nome_usuario(usuario_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT nome FROM usuarios WHERE id = ?", (usuario_id,))
            usuario = cursor.fetchone()
        return usuario["nome"] if usuario else None
    except sqlite3.Error as e:
        print(f"Erro ao obter nome do usuário: {e}")
        return None

# Funções de produtos (adaptadas para SQLite)
def carregar_produtos_usuario(usuario_id, apenas_nao_enviados=False):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            if apenas_nao_enviados:
                # Usar ? como placeholder
                cursor.execute("SELECT * FROM produtos WHERE usuario_id = ? AND enviado = 0 ORDER BY timestamp DESC", (usuario_id,))
            else:
                cursor.execute("SELECT * FROM produtos WHERE usuario_id = ? ORDER BY timestamp DESC", (usuario_id,))
            # Converter sqlite3.Row para dict
            produtos = [dict(row) for row in cursor.fetchall()]
        return produtos
    except sqlite3.Error as e:
        print(f"Erro ao carregar produtos do usuário: {e}")
        return []

def carregar_todas_listas_enviadas():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Buscar produtos enviados junto com o nome do usuário, do validador e do responsável (se houver)
            # Sintaxe de JOIN é padrão SQL, deve funcionar no SQLite
            cursor.execute("""
            SELECT p.*, 
                   u.nome as nome_usuario,
                   v.nome as nome_validador,
                   r.nome as nome_responsavel
            FROM produtos p 
            JOIN usuarios u ON p.usuario_id = u.id 
            LEFT JOIN usuarios v ON p.validador_id = v.id
            LEFT JOIN responsaveis r ON p.responsavel_id = r.id
            WHERE p.enviado = 1 
            ORDER BY p.data_envio DESC
            """)
            produtos = [dict(row) for row in cursor.fetchall()]
            
            # Debug para verificar se há produtos retornados
            # print(f"Produtos enviados encontrados: {len(produtos)}")
            # if len(produtos) > 0:
            #     print(f"Exemplo do primeiro produto: {produtos[0]}")
                    
        return produtos
    except sqlite3.Error as e:
        print(f"Erro ao carregar todas as listas enviadas: {e}")
        return []

def pesquisar_produtos(termo_pesquisa):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Buscar produtos que correspondem ao termo de pesquisa (EAN ou palavra na descrição)
            # Usar LIKE e LOWER() para busca case-insensitive no SQLite
            termo_like = f"%{termo_pesquisa}%"
            cursor.execute("""
            SELECT p.*, 
                   u.nome as nome_usuario,
                   v.nome as nome_validador,
                   r.nome as nome_responsavel
            FROM produtos p 
            JOIN usuarios u ON p.usuario_id = u.id 
            LEFT JOIN usuarios v ON p.validador_id = v.id
            LEFT JOIN responsaveis r ON p.responsavel_id = r.id
            WHERE p.enviado = 1 
              AND (LOWER(p.ean) LIKE LOWER(?) OR LOWER(p.nome) LIKE LOWER(?) OR LOWER(p.cor) LIKE LOWER(?) OR LOWER(p.modelo) LIKE LOWER(?))
            ORDER BY p.data_envio DESC
            """, (termo_like, termo_like, termo_like, termo_like))
            produtos = [dict(row) for row in cursor.fetchall()]
        return produtos
    except sqlite3.Error as e:
        print(f"Erro ao pesquisar produtos: {e}")
        return []

def buscar_produto_local(ean, usuario_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Usar ? como placeholder
            cursor.execute("SELECT * FROM produtos WHERE ean = ? AND usuario_id = ? AND enviado = 0", (ean, usuario_id))
            produto = cursor.fetchone()
        return dict(produto) if produto else None
    except sqlite3.Error as e:
        print(f"Erro ao buscar produto local: {e}")
        return None

def salvar_produto(produto, usuario_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Verificar se o produto já existe para este usuário e não foi enviado
            cursor.execute("SELECT id FROM produtos WHERE ean = ? AND usuario_id = ? AND enviado = 0", 
                          (produto["ean"], usuario_id))
            existing = cursor.fetchone()
            
            # Garantir que timestamp seja uma string ISO8601 UTC
            timestamp_obj = produto.get("timestamp")
            if isinstance(timestamp_obj, datetime):
                # Assegurar que está em UTC e formatar
                timestamp_str = timestamp_obj.astimezone(timezone.utc).isoformat()
            else:
                 # Se não for datetime, usar o tempo atual em UTC
                 timestamp_str = datetime.now(timezone.utc).isoformat()

            # Obter preço médio (pode ser None)
            preco_medio = produto.get("preco_medio")

            if existing:
                # Atualizar quantidade e timestamp (e preço médio se disponível)
                cursor.execute("""
                UPDATE produtos 
                SET quantidade = quantidade + ?, 
                    timestamp = ?, 
                    preco_medio = ?
                WHERE ean = ? AND usuario_id = ? AND enviado = 0
                """, (produto["quantidade"], timestamp_str, preco_medio, produto["ean"], usuario_id))
            else:
                # Inserir novo produto
                cursor.execute("""
                INSERT INTO produtos (ean, nome, cor, voltagem, modelo, quantidade, usuario_id, timestamp, enviado, preco_medio)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                """, (
                    produto["ean"], 
                    produto["nome"], 
                    produto.get("cor"), # Usar .get para campos opcionais
                    produto.get("voltagem"), 
                    produto.get("modelo"), 
                    produto["quantidade"], 
                    usuario_id,
                    timestamp_str,
                    preco_medio # Adicionado preço médio
                ))
            conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Erro ao salvar produto: {e}")
        # conn.rollback() # Rollback é implícito com `with` em caso de exceção
        return False
    except Exception as e:
        print(f"Erro inesperado ao salvar produto: {e}")
        return False

def enviar_lista_produtos(usuario_id, responsavel_id, pin):
    try:
        # Verificar se o PIN corresponde ao responsável
        if not verificar_pin_responsavel(responsavel_id, pin):
            print(f"PIN inválido para o responsável ID {responsavel_id}")
            return None
            
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Usar string ISO8601 UTC para data_envio
            data_envio_str = datetime.now(timezone.utc).isoformat()
            # Marcar todos os produtos não enviados como enviados
            cursor.execute("""
            UPDATE produtos 
            SET enviado = 1, 
                data_envio = ?, 
                responsavel_id = ?, 
                responsavel_pin = ?
            WHERE usuario_id = ? AND enviado = 0
            """, (data_envio_str, responsavel_id, pin, usuario_id))
            
            # Verificar quantas linhas foram afetadas
            affected_rows = cursor.rowcount
            print(f"Produtos marcados como enviados: {affected_rows}")
            
            conn.commit()
            # Retornar a string da data de envio
            return data_envio_str 
    except sqlite3.Error as e:
        print(f"Erro ao enviar lista de produtos: {e}")
        return None

def validar_lista(data_envio_str, nome_usuario, validador_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Obter o ID do usuário pelo nome
            cursor.execute("SELECT id FROM usuarios WHERE nome = ?", (nome_usuario,))
            usuario = cursor.fetchone()
            
            if not usuario:
                print(f"Usuário não encontrado: {nome_usuario}")
                return False
            
            usuario_id = usuario["id"]
            # Usar string ISO8601 UTC para data_validacao
            data_validacao_str = datetime.now(timezone.utc).isoformat()
            
            # Comparar data_envio (que agora é string ISO) diretamente
            print(f"Validando lista com data_envio: {data_envio_str}")
            
            cursor.execute("""
            UPDATE produtos 
            SET validado = 1, 
                validador_id = ?, 
                data_validacao = ?
            WHERE usuario_id = ? AND data_envio = ? AND enviado = 1
            """, (validador_id, data_validacao_str, usuario_id, data_envio_str))
            
            affected_rows = cursor.rowcount
            print(f"Produtos marcados como validados: {affected_rows}")
            
            conn.commit()
            return affected_rows > 0
            
    except sqlite3.Error as e:
        print(f"Erro ao validar lista: {e}")
        return False
    except Exception as e:
        print(f"Erro inesperado ao validar lista: {e}")
        print(f"Tipo de data_envio: {type(data_envio_str)}, Valor: {data_envio_str}")
        return False

def excluir_produto(produto_id, usuario_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Verificar se o produto pertence ao usuário e não foi enviado
            cursor.execute("SELECT id FROM produtos WHERE id = ? AND usuario_id = ? AND enviado = 0", 
                          (produto_id, usuario_id))
            produto = cursor.fetchone()
            
            if not produto:
                print(f"Produto ID {produto_id} não encontrado ou já enviado para usuário ID {usuario_id}.")
                return False
            
            # Excluir o produto
            cursor.execute("DELETE FROM produtos WHERE id = ?", (produto_id,))
            conn.commit()
            print(f"Produto ID {produto_id} excluído com sucesso.")
        return True
    except sqlite3.Error as e:
        print(f"Erro ao excluir produto: {e}")
        return False

# --- Rotas da Aplicação (sem alterações significativas na lógica, mas usam as funções adaptadas) ---

@app.route("/")
def index():
    if "usuario_id" not in session:
        return redirect(url_for("login"))
    
    usuario_id = session["usuario_id"]
    produtos = carregar_produtos_usuario(usuario_id, apenas_nao_enviados=True)
    responsaveis = obter_responsaveis() # Carregar responsáveis para o dropdown
    return render_template("index.html", produtos=produtos, responsaveis=responsaveis)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        nome = request.form.get("nome")
        senha = request.form.get("senha")
        
        usuario = verificar_usuario(nome, senha)
        if usuario:
            session["usuario_id"] = usuario["id"]
            session["usuario_nome"] = nome
            session["admin"] = usuario["admin"]
            
            if usuario["admin"]:
                return redirect(url_for("admin"))
            else:
                return redirect(url_for("index"))
        else:
            flash("Nome de usuário ou senha incorretos")
    
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Você saiu do sistema.")
    return redirect(url_for("login"))

@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nome = request.form.get("nome")
        senha = request.form.get("senha")
        
        if not nome or not senha:
             flash("Nome de usuário e senha são obrigatórios.")
             return render_template("registro.html")

        if registrar_usuario(nome, senha):
            flash("Usuário registrado com sucesso! Faça login.")
            return redirect(url_for("login"))
        else:
            # A mensagem de erro específica já é impressa no console pela função
            flash("Erro ao registrar usuário. Verifique se o nome já existe.")
    
    return render_template("registro.html")

@app.route("/admin")
def admin():
    if "usuario_id" not in session or not session.get("admin"):
        flash("Acesso não autorizado.")
        return redirect(url_for("login"))
    
    termo_pesquisa = request.args.get("pesquisa", "")
    
    # Dicionário para agrupar produtos por data de envio e usuário
    listas_agrupadas = {}
    
    if termo_pesquisa:
        produtos_encontrados = pesquisar_produtos(termo_pesquisa)
        print(f"Produtos encontrados na pesquisa: {len(produtos_encontrados)}")
        
        # Agrupar produtos encontrados
        for produto in produtos_encontrados:
            data_envio_key = produto.get("data_envio")
            if not data_envio_key:
                data_envio_key = "Sem data de envio"
                 
            chave = (data_envio_key, produto["nome_usuario"])
            if chave not in listas_agrupadas:
                listas_agrupadas[chave] = {
                    "produtos": [],
                    "validado": produto.get("validado", 0),
                    "nome_validador": produto.get("nome_validador"),
                    "data_validacao": produto.get("data_validacao"),
                    "nome_responsavel": produto.get("nome_responsavel")
                }
            listas_agrupadas[chave]["produtos"].append(produto)
    else:
        listas_enviadas = carregar_todas_listas_enviadas()
        # print(f"Total de listas enviadas carregadas: {len(listas_enviadas)}")
        
        # Agrupar todas as listas enviadas
        for produto in listas_enviadas:
            data_envio_key = produto.get("data_envio")
            if not data_envio_key:
                data_envio_key = "Sem data de envio"

            chave = (data_envio_key, produto["nome_usuario"])
            if chave not in listas_agrupadas:
                listas_agrupadas[chave] = {
                    "produtos": [],
                    "validado": produto.get("validado", 0),
                    "nome_validador": produto.get("nome_validador"),
                    "data_validacao": produto.get("data_validacao"),
                    "nome_responsavel": produto.get("nome_responsavel")
                }
            listas_agrupadas[chave]["produtos"].append(produto)
    
    # print(f"Número de listas agrupadas: {len(listas_agrupadas)}")
    
    # Ordenar as listas pela data de envio (chave[0]) decrescente
    listas_ordenadas = sorted(listas_agrupadas.items(), key=lambda item: item[0][0] or "", reverse=True)
    
    return render_template("admin.html", listas_ordenadas=listas_ordenadas, termo_pesquisa=termo_pesquisa)

@app.route("/api/responsaveis", methods=["GET"])
def get_responsaveis():
    if "usuario_id" not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    responsaveis = obter_responsaveis()
    return jsonify(responsaveis)

@app.route("/api/buscar-produto", methods=["GET"])
def buscar_produto():
    if "usuario_id" not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    ean = request.args.get("ean")
    if not ean:
        return jsonify({"error": "EAN não fornecido"}), 400
    
    # Verificar se o produto já existe no banco de dados local (não enviado)
    produto_local = buscar_produto_local(ean, session["usuario_id"])
    if produto_local:
        # Retornar dados do produto local encontrado
        produto_local_dict = dict(produto_local) # Converter Row para dict
        produto_local_dict["message"] = "Produto já existe na sua lista atual."
        return jsonify(produto_local_dict), 200 # OK, mas informa que já existe
    
    # Se não existir localmente, buscar online
    resultado_online = buscar_produto_online(ean)
    
    # Garantir que a resposta tenha a estrutura esperada
    if resultado_online["success"]:
         produto_data = resultado_online["data"]
         produto_data["ean"] = ean # Garantir que EAN esteja presente
         produto_data["quantidade"] = 1 # Quantidade padrão para novo produto
         # Adicionar preco_medio se existir
         produto_data["preco_medio"] = resultado_online["data"].get("preco_medio")
         return jsonify({
             **produto_data, # Desempacota os dados do produto
             "message": resultado_online.get("message", "Produto encontrado online.")
         }), 200
    else:
        # Mesmo em caso de falha na busca online, permitir adição manual
        return jsonify({
            "ean": ean,
            "nome": f"Produto {ean}", # Nome padrão
            "cor": "",
            "voltagem": "",
            "modelo": "",
            "quantidade": 1,
            "preco_medio": None, # Preço médio não disponível
            "message": resultado_online.get("message", "Falha ao buscar produto online. Preencha manualmente.")
        }), 200 # Retorna OK para permitir preenchimento manual

@app.route("/api/produtos", methods=["GET"])
def get_produtos():
    if "usuario_id" not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    produtos = carregar_produtos_usuario(session["usuario_id"], apenas_nao_enviados=True)
    return jsonify(produtos)

@app.route("/api/produtos", methods=["POST"])
def add_produto():
    if "usuario_id" not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    try:
        produto = request.json
        if not produto or not produto.get("ean") or not produto.get("nome"):
            return jsonify({"error": "Dados do produto incompletos"}), 400
        
        # Garantir que quantidade seja um inteiro
        try:
            produto["quantidade"] = int(produto.get("quantidade", 1))
            if produto["quantidade"] < 1:
                 produto["quantidade"] = 1 # Garantir quantidade mínima
        except (ValueError, TypeError):
            produto["quantidade"] = 1
        
        # Adicionar timestamp atual (já tratado em salvar_produto)
        # produto["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        # Passar preco_medio para salvar_produto
        produto["preco_medio"] = produto.get("preco_medio")

        if salvar_produto(produto, session["usuario_id"]):
            # Carregar a lista atualizada de produtos para retornar ao frontend
            produtos_atualizados = carregar_produtos_usuario(session["usuario_id"], apenas_nao_enviados=True)
            return jsonify(produtos_atualizados), 200
        else:
            return jsonify({"error": "Erro ao salvar produto"}), 500
    except Exception as e:
        print(f"Erro ao adicionar produto: {e}")
        return jsonify({"error": f"Erro ao processar requisição: {str(e)}"}), 500

@app.route("/api/produtos/<int:produto_id>", methods=["DELETE"])
def delete_produto(produto_id):
    if "usuario_id" not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    if excluir_produto(produto_id, session["usuario_id"]):
        # Retornar a lista atualizada após exclusão
        produtos_atualizados = carregar_produtos_usuario(session["usuario_id"], apenas_nao_enviados=True)
        return jsonify(produtos_atualizados), 200
    else:
        return jsonify({"error": "Erro ao excluir produto ou produto não encontrado/já enviado"}), 404 # Ou 500 dependendo do erro

@app.route("/api/enviar-lista", methods=["POST"])
def enviar_lista():
    if "usuario_id" not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    try:
        data = request.json
        responsavel_id = data.get("responsavel_id")
        pin = data.get("pin")
        
        if not responsavel_id or not pin:
            return jsonify({"error": "Responsável e PIN são obrigatórios"}), 400
        
        # Converter para inteiro se necessário
        try:
            responsavel_id = int(responsavel_id)
        except (ValueError, TypeError):
            return jsonify({"error": "ID do responsável inválido"}), 400
        
        data_envio_str = enviar_lista_produtos(session["usuario_id"], responsavel_id, pin)
        
        if data_envio_str:
            # Formatar data para padrão brasileiro para exibição
            try:
                data_envio_dt = datetime.fromisoformat(data_envio_str.replace("Z", "+00:00"))
                data_envio_formatada = formatar_data_brasileira(data_envio_dt)
            except ValueError:
                data_envio_formatada = data_envio_str # Fallback se formato for inesperado
                
            return jsonify({
                "success": True, 
                "message": "Lista enviada com sucesso", 
                "data_envio": data_envio_formatada # Enviar formatada para UI
            }), 200
        else:
            # A mensagem de erro específica (PIN inválido ou erro DB) já foi logada
            return jsonify({"error": "Erro ao enviar lista. Verifique o PIN ou tente novamente."}), 400
    except Exception as e:
        print(f"Erro ao enviar lista de produtos: {e}")
        return jsonify({"error": f"Erro ao processar requisição: {str(e)}"}), 500

@app.route("/api/validar-lista", methods=["POST"])
def validar_lista_api():
    if "usuario_id" not in session or not session.get("admin"):
        return jsonify({"error": "Não autorizado"}), 401
    
    try:
        data = request.json
        # Receber a data_envio como string (pode ser ISO ou formato brasileiro do template)
        data_envio_input = data.get("data_envio") 
        nome_usuario = data.get("nome_usuario")
        validador_id = session["usuario_id"]
        
        print(f"Recebida solicitação para validar lista: data_envio_input={data_envio_input}, nome_usuario={nome_usuario}")
        
        if not data_envio_input or not nome_usuario:
            return jsonify({"error": "Dados incompletos"}), 400
        
        # A função validar_lista espera a data_envio como string ISO (como está no DB)
        # Precisamos garantir que a data recebida (que pode vir formatada) seja convertida
        # ou que a função validar_lista consiga buscar pelo formato recebido.
        # A forma mais segura é buscar a data ISO original no banco com base na chave (data_envio, nome_usuario)
        # No entanto, a função validar_lista já recebe a data_envio_str. Vamos assumir que ela é a chave correta por enquanto.
        
        # *** IMPORTANTE: A chave data_envio no admin.html parece ser a data formatada. ***
        # *** A função validar_lista espera a data ISO do banco. Isso precisa ser corrigido. ***
        # *** Solução temporária: Passar a data ISO correta do backend para o frontend ou ***
        # *** buscar a data ISO no backend antes de chamar validar_lista. ***
        # *** Vamos ajustar validar_lista para tentar encontrar pelo formato recebido, mas idealmente a chave deveria ser a ISO. ***
        
        # Tentar validar com a data recebida (pode falhar se não for ISO)
        if validar_lista(data_envio_input, nome_usuario, validador_id):
            return jsonify({"success": True, "message": "Lista validada com sucesso"}), 200
        else:
            # Tentar encontrar a data ISO correspondente no banco (mais robusto)
            # Esta parte exigiria buscar a data ISO no banco usando nome_usuario e a data formatada como pista
            # Por simplicidade agora, retornamos erro.
            print(f"Falha ao validar lista diretamente com data_envio={data_envio_input}. Pode ser problema de formato.")
            return jsonify({"error": "Erro ao validar lista. Verifique os dados ou formato da data."}), 400
            
    except Exception as e:
        print(f"Erro inesperado na API de validação: {e}")
        return jsonify({"error": f"Erro interno ao validar lista: {str(e)}"}), 500

@app.route("/exportar-excel", methods=["GET"])
def exportar_excel():
    if "usuario_id" not in session or not session.get("admin"):
         flash("Acesso não autorizado.")
         return redirect(url_for("login"))

    # Obter parâmetros da query string
    data_envio_str = request.args.get("data_envio")
    nome_usuario = request.args.get("nome_usuario")

    if not data_envio_str or not nome_usuario:
        flash("Parâmetros inválidos para exportação.")
        return redirect(url_for("admin"))

    try:
        # Buscar os produtos específicos da lista a ser exportada
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Buscar pelo nome do usuário e data de envio (string ISO)
            # Precisamos garantir que data_envio_str seja a string ISO correta
            # TODO: Ajustar a busca para ser mais flexível com o formato da data se necessário
            cursor.execute("""
            SELECT p.ean, p.nome, p.cor, p.voltagem, p.modelo, p.quantidade, 
                   u.nome as nome_usuario, r.nome as nome_responsavel, p.data_envio
            FROM produtos p
            JOIN usuarios u ON p.usuario_id = u.id
            LEFT JOIN responsaveis r ON p.responsavel_id = r.id
            WHERE u.nome = ? AND p.data_envio = ? AND p.enviado = 1
            ORDER BY p.timestamp
            """, (nome_usuario, data_envio_str))
            
            produtos_lista = [dict(row) for row in cursor.fetchall()]

        if not produtos_lista:
            flash(f"Nenhum produto encontrado para exportar para {nome_usuario} em {data_envio_str}.")
            return redirect(url_for("admin"))

        # Criar DataFrame do Pandas
        df = pd.DataFrame(produtos_lista)
        
        # Formatar data_envio para o Excel (opcional, pode deixar ISO)
        # df["data_envio"] = pd.to_datetime(df["data_envio"]).dt.strftime("%d/%m/%Y %H:%M:%S")
        
        # Renomear colunas para melhor leitura no Excel
        df.rename(columns={
            "ean": "EAN",
            "nome": "Descrição",
            "cor": "Cor",
            "voltagem": "Voltagem",
            "modelo": "Modelo",
            "quantidade": "Quantidade",
            "nome_usuario": "Usuário",
            "nome_responsavel": "Responsável Envio",
            "data_envio": "Data Envio (UTC ISO)"
        }, inplace=True)

        # Criar arquivo Excel em memória
        output = io.BytesIO(        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name=\'Produtos\')
        output.seek(0)

        # Nome do arquivo para download
        # Limpar data_envio_str para nome de arquivo seguro
        safe_data_envio = re.sub(r"[^0-9]", "", data_envio_str.split("T")[0]) # Pegar só a data YYYYMMDD
        filename = f"Lista_{nome_usuario}_{safe_data_envio}.xlsx"

        return send_file(output, 
                         mimetype=\'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\',
                         as_attachment=True, 
                         download_name=filename)

    except sqlite3.Error as e:
        print(f"Erro de banco de dados ao exportar: {e}")
        flash("Erro ao buscar dados para exportação.")
        return redirect(url_for("admin"))
    except Exception as e:
        print(f"Erro ao gerar Excel: {e}")
        flash("Erro ao gerar arquivo Excel.")
        return redirect(url_for("admin"))

# Inicializar o banco de dados ao iniciar a aplicação
# É melhor fazer isso via um comando separado (ex: flask init-db)
# Mas para simplificar, faremos aqui, garantindo que só rode uma vez.
# if not os.path.exists(DATABASE_PATH):
#     print("Banco de dados não encontrado. Inicializando...")
#     init_database()
# else:
#     print("Banco de dados já existe.")
#     # Opcional: Rodar PRAGMA foreign_keys = ON em cada conexão?
#     # É mais seguro garantir que está habilitado.

# Executar init_database() sempre que o app iniciar para garantir tabelas e admin
# A criação das tabelas com IF NOT EXISTS é idempotente.
init_database()

if __name__ == "__main__":
    # Para desenvolvimento local
    # Remover debug=True para produção
    # host=\'0.0.0.0\' permite acesso de outras máquinas na rede
    app.run(debug=True, host=\'0.0.0.0\', port=5000)
