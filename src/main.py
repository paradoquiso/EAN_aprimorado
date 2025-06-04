# -*- coding: utf-8 -*-
import sys
import os
import sqlite3
from datetime import datetime, timezone
import io
import requests
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
import pandas as pd
import json
from werkzeug.security import generate_password_hash, check_password_hash
from src.utils import formatar_data_brasileira
from src.mercado_livre import buscar_produto_por_ean as buscar_produto_online

# Imports adicionados para OAuth e PKCE
import secrets
import hashlib
import base64
import re # Importar re para limpar nome de arquivo

app = Flask(__name__)
# É CRUCIAL usar uma chave secreta forte e, preferencialmente, de variável de ambiente
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "ean_app_secret_key_default_dev_only") 

# --- Configurações do Mercado Livre --- 
# Substitua por suas credenciais ou use variáveis de ambiente (recomendado!)
ML_CLIENT_ID = os.environ.get("ML_CLIENT_ID", "5127568931658868") 
ML_CLIENT_SECRET = os.environ.get("ML_CLIENT_SECRET", "u6SV0QlYRqNgCYHvkebe7etpxwYRC1EN")
# Certifique-se que esta URI está registrada no painel do Mercado Livre
ML_REDIRECT_URI = os.environ.get("ML_REDIRECT_URI", "https://ean-aprimorado.onrender.com/ml_callback") 
ML_AUTH_URL = "https://auth.mercadolivre.com.br/authorization"
ML_TOKEN_URL = "https://api.mercadolibre.com/oauth/token"
# --------------------------------------

# Registrar filtro Jinja2 para formatação de data brasileira
@app.template_filter("data_brasileira")
def data_brasileira_filter(data):
    if isinstance(data, str):
        try:
            data = datetime.fromisoformat(data.replace("Z", "+00:00"))
        except ValueError:
            try:
                 data = datetime.strptime(data, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                 try:
                     data = datetime.strptime(data, "%Y-%m-%d %H:%M:%S")
                 except ValueError:
                     return data
    return formatar_data_brasileira(data)

# Configuração do banco de dados SQLite
DATABASE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "produtos.db")
print(f"Usando banco de dados SQLite em: {DATABASE_PATH}")

# Função auxiliar para obter conexão SQLite
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row 
    return conn

# Inicializar o banco de dados
def init_database():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys = ON;")
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL UNIQUE,
                senha_hash TEXT NOT NULL,
                admin INTEGER DEFAULT 0,
                ml_access_token TEXT, -- Novo campo
                ml_refresh_token TEXT, -- Novo campo
                ml_token_expires_at REAL -- Novo campo (timestamp float)
            );
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS responsaveis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL UNIQUE,
                pin TEXT NOT NULL
            );
            """)
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
                timestamp TEXT,
                enviado INTEGER DEFAULT 0,
                data_envio TEXT,
                validado INTEGER DEFAULT 0,
                validador_id INTEGER,
                data_validacao TEXT,
                responsavel_id INTEGER,
                responsavel_pin TEXT,
                preco_medio REAL,
                FOREIGN KEY (usuario_id) REFERENCES usuarios (id),
                FOREIGN KEY (validador_id) REFERENCES usuarios (id),
                FOREIGN KEY (responsavel_id) REFERENCES responsaveis (id)
            );
            """)
            
            # Adicionar colunas de token à tabela usuarios se não existirem
            try:
                cursor.execute("ALTER TABLE usuarios ADD COLUMN ml_access_token TEXT")
                cursor.execute("ALTER TABLE usuarios ADD COLUMN ml_refresh_token TEXT")
                cursor.execute("ALTER TABLE usuarios ADD COLUMN ml_token_expires_at REAL")
                print("Colunas de token do Mercado Livre adicionadas à tabela usuarios.")
            except sqlite3.OperationalError as alter_error:
                # Ignorar erro se a coluna já existe
                if "duplicate column name" not in str(alter_error):
                    raise alter_error
                # else: print("Colunas de token já existem.")

            cursor.execute("SELECT COUNT(*) FROM usuarios")
            user_count = cursor.fetchone()[0]
            if user_count == 0:
                cursor.execute("SELECT * FROM usuarios WHERE admin = 1")
                admin_user = cursor.fetchone()
                if not admin_user:
                    admin_hash = generate_password_hash("admin")
                    cursor.execute("INSERT INTO usuarios (nome, senha_hash, admin) VALUES (?, ?, ?)", 
                                  ("admin", admin_hash, 1))
            inicializar_responsaveis(conn)
            conn.commit()
            print("Banco de dados SQLite inicializado/verificado com sucesso.")
    except sqlite3.Error as e:
        print(f"Erro ao inicializar o banco de dados SQLite: {e}")

# Inicializar responsáveis com PINs
def inicializar_responsaveis(conn):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM responsaveis")
        count = cursor.fetchone()[0]
        if count == 0:
            responsaveis = [
                ("Liliane", "5584"), ("Rogerio", "9841"),
                ("Celso", "2122"), ("Marcos", "6231")
            ]
            cursor.executemany("INSERT INTO responsaveis (nome, pin) VALUES (?, ?)", responsaveis)
            print(f"Responsáveis inicializados: {len(responsaveis)}")
    except sqlite3.Error as e:
        print(f"Erro ao inicializar responsáveis: {e}")

# Obter todos os responsáveis
def obter_responsaveis():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, nome FROM responsaveis ORDER BY nome")
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"Erro ao obter responsáveis: {e}")
        return []

# Verificar PIN do responsável
def verificar_pin_responsavel(responsavel_id, pin):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT pin FROM responsaveis WHERE id = ?", (responsavel_id,))
            resultado = cursor.fetchone()
            return bool(resultado and resultado["pin"] == pin)
    except sqlite3.Error as e:
        print(f"Erro ao verificar PIN do responsável: {e}")
        return False

# Obter nome do responsável
def obter_nome_responsavel(responsavel_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT nome FROM responsaveis WHERE id = ?", (responsavel_id,))
            resultado = cursor.fetchone()
            return resultado["nome"] if resultado else None
    except sqlite3.Error as e:
        print(f"Erro ao obter nome do responsável: {e}")
        return None

# --- Funções de Autenticação e Usuário ---
def registrar_usuario(nome, senha):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            senha_hash = generate_password_hash(senha)
            cursor.execute("INSERT INTO usuarios (nome, senha_hash) VALUES (?, ?)", (nome, senha_hash))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        print(f"Erro: Nome de usuário \'{nome}\' já existe.")
        return False
    except sqlite3.Error as e:
        print(f"Erro ao registrar usuário: {e}")
        return False

def verificar_usuario(nome, senha):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM usuarios WHERE nome = ?", (nome,))
            usuario = cursor.fetchone()
        if usuario and check_password_hash(usuario["senha_hash"], senha):
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

def salvar_tokens_ml(usuario_id, access_token, refresh_token, expires_in):
    try:
        expires_at = datetime.now(timezone.utc).timestamp() + expires_in
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE usuarios 
            SET ml_access_token = ?, ml_refresh_token = ?, ml_token_expires_at = ?
            WHERE id = ?
            """, (access_token, refresh_token, expires_at, usuario_id))
            conn.commit()
            print(f"Tokens do ML salvos para o usuário {usuario_id}")
            return True
    except sqlite3.Error as e:
        print(f"Erro ao salvar tokens do ML para usuário {usuario_id}: {e}")
        return False

def obter_tokens_ml(usuario_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ml_access_token, ml_refresh_token, ml_token_expires_at FROM usuarios WHERE id = ?", (usuario_id,))
            tokens = cursor.fetchone()
            if tokens and tokens["ml_access_token"]:
                return dict(tokens)
            return None
    except sqlite3.Error as e:
        print(f"Erro ao obter tokens do ML para usuário {usuario_id}: {e}")
        return None

# --- Funções de Produtos ---
def carregar_produtos_usuario(usuario_id, apenas_nao_enviados=False):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            sql = "SELECT * FROM produtos WHERE usuario_id = ?" + (" AND enviado = 0" if apenas_nao_enviados else "") + " ORDER BY timestamp DESC"
            cursor.execute(sql, (usuario_id,))
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"Erro ao carregar produtos do usuário: {e}")
        return []

def carregar_todas_listas_enviadas():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT p.*, u.nome as nome_usuario, v.nome as nome_validador, r.nome as nome_responsavel
            FROM produtos p JOIN usuarios u ON p.usuario_id = u.id 
            LEFT JOIN usuarios v ON p.validador_id = v.id
            LEFT JOIN responsaveis r ON p.responsavel_id = r.id
            WHERE p.enviado = 1 ORDER BY p.data_envio DESC
            """)
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"Erro ao carregar todas as listas enviadas: {e}")
        return []

def pesquisar_produtos(termo_pesquisa):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            termo_like = f"%{termo_pesquisa}%"
            cursor.execute("""
            SELECT p.*, u.nome as nome_usuario, v.nome as nome_validador, r.nome as nome_responsavel
            FROM produtos p JOIN usuarios u ON p.usuario_id = u.id 
            LEFT JOIN usuarios v ON p.validador_id = v.id
            LEFT JOIN responsaveis r ON p.responsavel_id = r.id
            WHERE p.enviado = 1 AND (LOWER(p.ean) LIKE LOWER(?) OR LOWER(p.nome) LIKE LOWER(?) OR LOWER(p.cor) LIKE LOWER(?) OR LOWER(p.modelo) LIKE LOWER(?))
            ORDER BY p.data_envio DESC
            """, (termo_like, termo_like, termo_like, termo_like))
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"Erro ao pesquisar produtos: {e}")
        return []

def buscar_produto_local(ean, usuario_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
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
            cursor.execute("SELECT id FROM produtos WHERE ean = ? AND usuario_id = ? AND enviado = 0", (produto["ean"], usuario_id))
            existing = cursor.fetchone()
            timestamp_obj = produto.get("timestamp")
            timestamp_str = (timestamp_obj.astimezone(timezone.utc).isoformat() 
                             if isinstance(timestamp_obj, datetime) 
                             else datetime.now(timezone.utc).isoformat())
            preco_medio = produto.get("preco_medio")

            if existing:
                cursor.execute("UPDATE produtos SET quantidade = quantidade + ?, timestamp = ?, preco_medio = ? WHERE ean = ? AND usuario_id = ? AND enviado = 0",
                               (produto["quantidade"], timestamp_str, preco_medio, produto["ean"], usuario_id))
            else:
                cursor.execute("INSERT INTO produtos (ean, nome, cor, voltagem, modelo, quantidade, usuario_id, timestamp, enviado, preco_medio) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
                               (produto["ean"], produto["nome"], produto.get("cor"), produto.get("voltagem"), produto.get("modelo"), produto["quantidade"], usuario_id, timestamp_str, preco_medio))
            conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Erro ao salvar produto: {e}")
        return False
    except Exception as e:
        print(f"Erro inesperado ao salvar produto: {e}")
        return False

def enviar_lista_produtos(usuario_id, responsavel_id, pin):
    try:
        if not verificar_pin_responsavel(responsavel_id, pin):
            print(f"PIN inválido para o responsável ID {responsavel_id}")
            return None # Retorna None para indicar falha de PIN
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            data_envio_str = datetime.now(timezone.utc).isoformat()
            cursor.execute("UPDATE produtos SET enviado = 1, data_envio = ?, responsavel_id = ?, responsavel_pin = ? WHERE usuario_id = ? AND enviado = 0",
                           (data_envio_str, responsavel_id, pin, usuario_id))
            affected_rows = cursor.rowcount
            conn.commit()
            print(f"Produtos marcados como enviados: {affected_rows}")
            return data_envio_str # Retorna a string da data de envio
    except sqlite3.Error as e:
        print(f"Erro ao enviar lista de produtos: {e}")
        return None # Retorna None em caso de erro de DB

def validar_lista(data_envio_str, nome_usuario, validador_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM usuarios WHERE nome = ?", (nome_usuario,))
            usuario = cursor.fetchone()
            if not usuario:
                print(f"Usuário não encontrado: {nome_usuario}")
                return False
            usuario_id = usuario["id"]
            data_validacao_str = datetime.now(timezone.utc).isoformat()
            print(f"Validando lista com data_envio: {data_envio_str}")
            cursor.execute("UPDATE produtos SET validado = 1, validador_id = ?, data_validacao = ? WHERE usuario_id = ? AND data_envio = ? AND enviado = 1",
                           (validador_id, data_validacao_str, usuario_id, data_envio_str))
            affected_rows = cursor.rowcount
            conn.commit()
            print(f"Produtos marcados como validados: {affected_rows}")
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
            cursor.execute("SELECT id FROM produtos WHERE id = ? AND usuario_id = ? AND enviado = 0", (produto_id, usuario_id))
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

# --- Rotas da Aplicação ---

@app.route("/")
def index():
    if "usuario_id" not in session:
        return redirect(url_for("login"))
    
    usuario_id = session["usuario_id"]
    produtos = carregar_produtos_usuario(usuario_id, apenas_nao_enviados=True)
    responsaveis = obter_responsaveis() # Carregar responsáveis para o dropdown
    
    # Verificar se o usuário já tem token do ML
    ml_tokens = obter_tokens_ml(usuario_id)
    ml_authorized = bool(ml_tokens and ml_tokens.get("ml_access_token"))

    return render_template("index.html", produtos=produtos, responsaveis=responsaveis, ml_authorized=ml_authorized)

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
    else:
        produtos_encontrados = carregar_todas_listas_enviadas()
        # print(f"Total de listas enviadas carregadas: {len(produtos_encontrados)}")
        
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
        produto_local_dict = dict(produto_local)
        produto_local_dict["message"] = "Produto já existe na sua lista atual."
        return jsonify(produto_local_dict), 200 # OK, mas informa que já existe
        
    # Se não existir localmente, buscar online
    resultado_online = buscar_produto_online(ean)
    
    # Garantir que a resposta tenha a estrutura esperada
    if resultado_online["success"]:
        produto_data = resultado_online["data"]
        # produto_data["ean"] = ean # Garantir que EAN esteja presente
        produto_data["quantidade"] = 1 # Quantidade padrão para novo produto
        # Adicionar preco_medio se existir
        produto_data["preco_medio"] = resultado_online["data"].get("preco_medio")
        return jsonify({
            "data": produto_data, # Desempacota os dados do produto
            "message": resultado_online.get("message", "Produto encontrado online.")
        }), 200
    else:
        # Mesmo em caso de falha na busca online, permitir adição manual
        return jsonify({
            "error": True,
            "data": {
                "ean": ean,
                "nome": f"Produto {ean}", # Nome padrão
                "cor": "",
                "voltagem": "",
                "modelo": "",
                "quantidade": 1,
                "preco_medio": None, # Preço médio não disponível
            },
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
        
    produto_data = request.json
    if not produto_data or "ean" not in produto_data or "nome" not in produto_data or "quantidade" not in produto_data:
        return jsonify({"error": "Dados incompletos"}), 400
        
    # Adiciona timestamp antes de salvar (pode ser string ou datetime)
    produto_data["timestamp"] = datetime.now(timezone.utc)
    
    if salvar_produto(produto_data, session["usuario_id"]):
        return jsonify({"message": "Produto adicionado/atualizado com sucesso"}), 201
    else:
        return jsonify({"error": "Erro ao salvar produto"}), 500

@app.route("/api/produtos/<int:produto_id>", methods=["DELETE"])
def delete_produto(produto_id):
    if "usuario_id" not in session:
        return jsonify({"error": "Não autorizado"}), 401
        
    if excluir_produto(produto_id, session["usuario_id"]):
        return jsonify({"message": "Produto excluído com sucesso"}), 200
    else:
        return jsonify({"error": "Erro ao excluir produto ou produto não encontrado/enviado"}), 404

@app.route("/api/enviar-lista", methods=["POST"])
def submit_lista():
    if "usuario_id" not in session:
        return jsonify({"error": "Não autorizado"}), 401
        
    data = request.json
    responsavel_id = data.get("responsavel_id")
    pin = data.get("pin")
    
    if not responsavel_id or not pin:
        return jsonify({"error": "Responsável e PIN são obrigatórios"}), 400
        
    data_envio = enviar_lista_produtos(session["usuario_id"], responsavel_id, pin)
    
    if data_envio is not None:
        return jsonify({"message": "Lista enviada com sucesso", "data_envio": data_envio}), 200
    else:
        # A função enviar_lista_produtos já imprime o erro específico (PIN ou DB)
        # Podemos retornar um erro genérico ou diferenciar baseado no retorno (se fosse mais granular)
        return jsonify({"error": "Falha ao enviar lista. Verifique o PIN ou contate o suporte."}), 400 # Ou 500 se for erro DB

@app.route("/api/validar-lista", methods=["POST"])
def api_validar_lista():
    if "usuario_id" not in session or not session.get("admin"):
        return jsonify({"error": "Acesso não autorizado"}), 401
        
    data = request.json
    data_envio = data.get("data_envio")
    nome_usuario = data.get("nome_usuario")
    validador_id = session["usuario_id"] # O admin logado é o validador
    
    if not data_envio or not nome_usuario:
        return jsonify({"error": "Dados incompletos para validação"}), 400
        
    if validar_lista(data_envio, nome_usuario, validador_id):
        return jsonify({"message": "Lista validada com sucesso"}), 200
    else:
        return jsonify({"error": "Erro ao validar lista ou nenhuma linha afetada"}), 500

@app.route("/exportar-lista", methods=["POST"])
def exportar_lista():
    if "usuario_id" not in session or not session.get("admin"):
        flash("Acesso não autorizado.")
        return redirect(url_for("login"))
        
    data_envio_str = request.form.get("data_envio")
    nome_usuario = request.form.get("nome_usuario")
    
    if not data_envio_str or not nome_usuario:
        flash("Dados da lista para exportação não fornecidos.")
        return redirect(url_for("admin"))

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Buscar ID do usuário pelo nome
            cursor.execute("SELECT id FROM usuarios WHERE nome = ?", (nome_usuario,))
            user_result = cursor.fetchone()
            if not user_result:
                flash(f"Usuário {nome_usuario} não encontrado.")
                return redirect(url_for("admin"))
            usuario_id = user_result["id"]

            # Buscar produtos da lista específica
            cursor.execute("""
            SELECT ean, nome, quantidade 
            FROM produtos 
            WHERE usuario_id = ? AND data_envio = ? AND enviado = 1
            ORDER BY timestamp
            """, (usuario_id, data_envio_str))
            
            produtos_lista = cursor.fetchall()

        if not produtos_lista:
            flash("Nenhum produto encontrado para esta lista.")
            return redirect(url_for("admin"))

        # Criar DataFrame com colunas na ordem correta
        df = pd.DataFrame([dict(row) for row in produtos_lista], columns=["ean", "nome", "quantidade"])
        # Renomear colunas para o Excel
        df.rename(columns={
            "ean": "EAN", 
            "nome": "DESCRIÇÃO", 
            "quantidade": "QUANTIDADE"
        }, inplace=True)

        # Criar arquivo Excel em memória
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Produtos")
        output.seek(0)

        # Nome do arquivo para download
        # Limpar data_envio_str para nome de arquivo seguro
        safe_data_envio = re.sub(r"[^0-9]", "", data_envio_str.split("T")[0]) # Pegar só a data YYYYMMDD
        filename = f"Lista_{nome_usuario}_{safe_data_envio}.xlsx"

        return send_file(output, 
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                         as_attachment=True, 
                         download_name=filename)

    except sqlite3.Error as e:
        print(f"Erro de banco de dados ao exportar: {e}")
        flash("Erro ao buscar dados para exportação.")
        return redirect(url_for("admin"))
    except Exception as e:
        print(f"Erro inesperado ao exportar: {e}")
        flash("Ocorreu um erro inesperado ao gerar o arquivo Excel.")
        return redirect(url_for("admin"))

# --- Rotas de Autorização Mercado Livre --- 

@app.route("/authorize_ml")
def authorize_ml():
    if "usuario_id" not in session:
        flash("Faça login para autorizar com o Mercado Livre.")
        return redirect(url_for("login"))

    # Gerar PKCE
    code_verifier = secrets.token_urlsafe(64)
    session["ml_code_verifier"] = code_verifier # Armazenar na sessão
    
    hashed = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(hashed).decode("ascii").replace("=", "")
    
    # Montar URL de autorização
    auth_params = {
        "response_type": "code",
        "client_id": ML_CLIENT_ID,
        "redirect_uri": ML_REDIRECT_URI,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    # Usar requests.PreparedRequest para codificar parâmetros corretamente
    req = requests.PreparedRequest()
    req.prepare_url(ML_AUTH_URL, params=auth_params)
    authorization_url = req.url

    print(f"Redirecionando para: {authorization_url}") # Debug
    return redirect(authorization_url)

@app.route("/ml_callback")
def ml_callback():
    if "usuario_id" not in session:
        flash("Sessão inválida ou expirada.")
        return redirect(url_for("login"))

    code = request.args.get("code")
    error = request.args.get("error")
    error_description = request.args.get("error_description")
    
    if error:
        flash(f"Erro na autorização do Mercado Livre: {error_description or error}")
        return redirect(url_for("index"))

    if not code:
        flash("Código de autorização não recebido do Mercado Livre.")
        return redirect(url_for("index"))

    code_verifier = session.pop("ml_code_verifier", None)
    if not code_verifier:
        flash("Verificador PKCE não encontrado na sessão. Tente autorizar novamente.")
        return redirect(url_for("index"))

    # Trocar código por token
    token_payload = {
        "grant_type": "authorization_code",
        "client_id": ML_CLIENT_ID,
        "client_secret": ML_CLIENT_SECRET,
        "code": code,
        "redirect_uri": ML_REDIRECT_URI,
        "code_verifier": code_verifier
    }
    
    try:
        print(f"Enviando para {ML_TOKEN_URL} payload: {token_payload}") # Debug
        response = requests.post(ML_TOKEN_URL, data=token_payload, headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        })
        response.raise_for_status() # Lança exceção para erros HTTP (4xx ou 5xx)
        
        token_data = response.json()
        print(f"Resposta do token ML: {token_data}") # Debug

        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in")

        if not access_token or not refresh_token or expires_in is None:
            flash("Resposta inválida ao obter tokens do Mercado Livre.")
            print(f"Token data incompleto: {token_data}")
            return redirect(url_for("index"))

        # Salvar tokens no banco de dados
        if salvar_tokens_ml(session["usuario_id"], access_token, refresh_token, expires_in):
            flash("Autorização com Mercado Livre concluída com sucesso!")
        else:
            flash("Autorização concluída, mas houve erro ao salvar os tokens.")
            
        return redirect(url_for("index"))

    except requests.exceptions.RequestException as e:
        flash(f"Erro de comunicação ao obter tokens do Mercado Livre: {e}")
        print(f"Erro na requisição de token: {e}")
        if e.response is not None:
            try:
                 print(f"Resposta do erro: {e.response.json()}")
            except json.JSONDecodeError:
                 print(f"Resposta do erro (não JSON): {e.response.text}")
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"Erro inesperado durante o callback do Mercado Livre: {e}")
        print(f"Erro inesperado no callback: {e}")
        return redirect(url_for("index"))

# --- Inicialização --- 

if __name__ == "__main__":
    init_database() # Garante que o DB e as tabelas existam
    # Para produção, use um servidor WSGI como Gunicorn
    # O Render usa Gunicorn por padrão, especificado no Procfile ou comando de start
    # app.run(debug=True) # debug=True NÃO é para produção!
    # app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000))) # Exemplo para Heroku/Render
    pass # Gunicorn cuidará de rodar a app
