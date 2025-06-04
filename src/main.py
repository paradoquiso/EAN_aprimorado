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
# Tenta ler variáveis de ambiente com nomes comuns, depois usa o padrão.
# Garanta que os nomes no Render correspondam a uma das opções (ML_CLIENT_ID ou MERCADO_LIVRE_CLIENT_ID)
ML_CLIENT_ID = os.environ.get("ML_CLIENT_ID") or os.environ.get("MERCADO_LIVRE_CLIENT_ID", "5127568931658868") 
ML_CLIENT_SECRET = os.environ.get("ML_CLIENT_SECRET", "u6SV0QlYRqNgCYHvkebe7etpxwYRC1EN")
# Certifique-se que esta URI está registrada no painel do Mercado Livre
ML_REDIRECT_URI = os.environ.get("ML_REDIRECT_URI", "https://ean-aprimorado.onrender.com/ml_callback") 
ML_AUTH_URL = "https://auth.mercadolivre.com.br/authorization"
ML_TOKEN_URL = "https://api.mercadolibre.com/oauth/token"
# --------------------------------------

# Configuração do banco de dados SQLite
# Usar um caminho relativo à raiz do projeto para compatibilidade com Render
DATABASE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "produtos.db")
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
            # Criar tabela usuarios se não existir
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL UNIQUE,
                senha_hash TEXT NOT NULL,
                admin INTEGER DEFAULT 0
            );
            """)
            # Adicionar colunas de token à tabela usuarios se não existirem
            try:
                cursor.execute("ALTER TABLE usuarios ADD COLUMN ml_access_token TEXT")
            except sqlite3.OperationalError:
                pass # Ignora se a coluna já existe
            try:
                cursor.execute("ALTER TABLE usuarios ADD COLUMN ml_refresh_token TEXT")
            except sqlite3.OperationalError:
                pass # Ignora se a coluna já existe
            try:
                cursor.execute("ALTER TABLE usuarios ADD COLUMN ml_token_expires_at REAL")
            except sqlite3.OperationalError:
                pass # Ignora se a coluna já existe

            # Criar tabela responsaveis se não existir
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS responsaveis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL UNIQUE,
                pin TEXT NOT NULL
            );
            """)
            # Criar tabela produtos se não existir
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
            
            # Verificar e inserir usuário admin padrão se não existir
            cursor.execute("SELECT COUNT(*) FROM usuarios WHERE nome = ?", ("admin",))
            admin_exists = cursor.fetchone()[0]
            if admin_exists == 0:
                admin_hash = generate_password_hash("admin")
                cursor.execute("INSERT INTO usuarios (nome, senha_hash, admin) VALUES (?, ?, ?)", 
                              ("admin", admin_hash, 1))
                print("Usuário admin padrão criado.")

            # Inicializar responsáveis se a tabela estiver vazia
            inicializar_responsaveis(conn)
            conn.commit()
            print("Banco de dados SQLite inicializado/verificado com sucesso.")
    except sqlite3.Error as e:
        print(f"Erro CRÍTICO ao inicializar o banco de dados SQLite: {e}")
        # Considerar lançar a exceção ou tratar de forma mais robusta

# Inicializar responsáveis com PINs (chamada por init_database)
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

# --- Forçar inicialização do DB ao iniciar a aplicação --- 
init_database()
# --------------------------------------------------------

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
            cursor.execute("UPDATE produtos SET validado = 1, validador_id = ?, data_validacao = ? WHERE usuario_id = ? AND data_envio = ? AND enviado = 1",
                           (validador_id, data_validacao_str, usuario_id, data_envio_str))
            conn.commit()
            print(f"Lista de {nome_usuario} enviada em {data_envio_str} validada por {validador_id}")
            return True
    except sqlite3.Error as e:
        print(f"Erro ao validar lista: {e}")
        return False

def excluir_produto(produto_id, usuario_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Garante que o usuário só pode excluir seus próprios produtos não enviados
            cursor.execute("DELETE FROM produtos WHERE id = ? AND usuario_id = ? AND enviado = 0", (produto_id, usuario_id))
            conn.commit()
            return cursor.rowcount > 0 # Retorna True se uma linha foi afetada
    except sqlite3.Error as e:
        print(f"Erro ao excluir produto: {e}")
        return False

# --- Rotas Flask ---
@app.route("/")
def index():
    if "usuario_id" not in session:
        return redirect(url_for("login"))
    usuario_id = session["usuario_id"]
    produtos = carregar_produtos_usuario(usuario_id, apenas_nao_enviados=True)
    
    # Verificar se o usuário atual tem tokens ML válidos
    ml_authorized = False
    tokens = obter_tokens_ml(usuario_id)
    if tokens and tokens.get("ml_token_expires_at") and tokens["ml_token_expires_at"] > datetime.now(timezone.utc).timestamp():
        ml_authorized = True
        
    return render_template("index.html", produtos=produtos, ml_authorized=ml_authorized)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        nome = request.form["nome"]
        senha = request.form["senha"]
        usuario = verificar_usuario(nome, senha)
        if usuario:
            session["usuario_id"] = usuario["id"]
            session["usuario_nome"] = usuario["nome"]
            session["is_admin"] = bool(usuario["admin"])
            flash("Login realizado com sucesso!", "success")
            return redirect(url_for("index"))
        else:
            flash("Nome de usuário ou senha inválidos.", "danger")
    return render_template("login.html")

@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nome = request.form["nome"]
        senha = request.form["senha"]
        if registrar_usuario(nome, senha):
            flash("Usuário registrado com sucesso! Faça o login.", "success")
            return redirect(url_for("login"))
        else:
            flash("Nome de usuário já existe ou ocorreu um erro.", "danger")
    return render_template("registro.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Você saiu do sistema.", "info")
    return redirect(url_for("login"))

@app.route("/admin")
def admin():
    if "usuario_id" not in session or not session.get("is_admin"):
        flash("Acesso não autorizado.", "danger")
        return redirect(url_for("login"))
    
    termo_pesquisa = request.args.get("q", "")
    if termo_pesquisa:
        listas_enviadas = pesquisar_produtos(termo_pesquisa)
    else:
        listas_enviadas = carregar_todas_listas_enviadas()
        
    return render_template("admin.html", listas=listas_enviadas, termo_pesquisa=termo_pesquisa)

# --- Rotas da API ---
@app.route("/api/produtos", methods=["GET"])
def get_produtos():
    if "usuario_id" not in session:
        return jsonify({"error": "Não autorizado"}), 401
    usuario_id = session["usuario_id"]
    produtos = carregar_produtos_usuario(usuario_id, apenas_nao_enviados=True)
    return jsonify(produtos)

@app.route("/api/produtos", methods=["POST"])
def add_produto():
    if "usuario_id" not in session:
        return jsonify({"error": "Não autorizado"}), 401
    usuario_id = session["usuario_id"]
    data = request.get_json()
    
    if not data or not data.get("ean") or not data.get("nome") or not data.get("quantidade"):
        return jsonify({"error": "Dados incompletos (EAN, Nome, Quantidade são obrigatórios)"}), 400
        
    produto = {
        "ean": data["ean"],
        "nome": data["nome"],
        "cor": data.get("cor"),
        "voltagem": data.get("voltagem"),
        "modelo": data.get("modelo"),
        "quantidade": int(data["quantidade"]),
        "preco_medio": data.get("preco_medio") # Adicionado
    }
    
    if salvar_produto(produto, usuario_id):
        return jsonify({"message": "Produto adicionado/atualizado com sucesso!"}), 201
    else:
        return jsonify({"error": "Erro ao salvar produto no banco de dados"}), 500

@app.route("/api/produtos/<int:produto_id>", methods=["DELETE"])
def delete_produto(produto_id):
    if "usuario_id" not in session:
        return jsonify({"error": "Não autorizado"}), 401
    usuario_id = session["usuario_id"]
    
    if excluir_produto(produto_id, usuario_id):
        # Retorna a lista atualizada após a exclusão
        produtos_atualizados = carregar_produtos_usuario(usuario_id, apenas_nao_enviados=True)
        return jsonify(produtos_atualizados), 200
    else:
        return jsonify({"error": "Erro ao excluir produto ou produto não encontrado/não pertence ao usuário"}), 404

@app.route("/api/buscar-produto", methods=["GET"])
def buscar_produto_api():
    if "usuario_id" not in session:
        return jsonify({"error": "Não autorizado"}), 401
    usuario_id = session["usuario_id"]
    ean = request.args.get("ean")
    if not ean:
        return jsonify({"error": "EAN não fornecido"}), 400

    # 1. Verificar se o produto já existe na lista local do usuário (não enviado)
    produto_local = buscar_produto_local(ean, usuario_id)
    if produto_local:
        produto_local["preco_medio"] = produto_local.get("preco_medio") # Garantir que o campo existe
        return jsonify({
            "message": f"Produto com EAN {ean} já existe na sua lista local.",
            "data": produto_local,
            "source": "local"
        }), 200

    # 2. Se não existe localmente, buscar online (Mercado Livre)
    resultado_online = buscar_produto_online(ean, usuario_id) # Passa usuario_id para obter tokens
    
    if resultado_online and resultado_online.get("nome"): # Verifica se encontrou nome
        return jsonify({
            "message": "Produto encontrado online.",
            "data": resultado_online,
            "source": "online"
        }), 200
    else:
        # Mesmo se não encontrar online, permite adicionar manualmente
        return jsonify({
            "message": "Produto não encontrado online. Preencha os dados manualmente.",
            "data": {"ean": ean, "nome": "", "cor": "", "voltagem": "", "modelo": "", "quantidade": 1, "preco_medio": None},
            "source": "manual"
        }), 200 # Retorna 200 para permitir preenchimento

@app.route("/api/responsaveis", methods=["GET"])
def get_responsaveis():
    if "usuario_id" not in session:
        return jsonify({"error": "Não autorizado"}), 401
    responsaveis = obter_responsaveis()
    return jsonify(responsaveis)

@app.route("/api/enviar-lista", methods=["POST"])
def enviar_lista_api():
    if "usuario_id" not in session:
        return jsonify({"error": "Não autorizado"}), 401
    usuario_id = session["usuario_id"]
    data = request.get_json()
    
    if not data or not data.get("responsavel_id") or not data.get("pin"):
        return jsonify({"error": "Responsável e PIN são obrigatórios"}), 400
        
    responsavel_id = data["responsavel_id"]
    pin = data["pin"]
    
    data_envio = enviar_lista_produtos(usuario_id, responsavel_id, pin)
    
    if data_envio is None and not verificar_pin_responsavel(responsavel_id, pin): # Verifica se falhou por PIN inválido
         return jsonify({"error": "PIN inválido para o responsável selecionado."}), 403
    elif data_envio:
        return jsonify({"message": f"Lista enviada com sucesso em {formatar_data_brasileira(data_envio)}."}), 200
    else:
        return jsonify({"error": "Erro ao enviar a lista ou lista vazia."}), 500

@app.route("/api/validar-lista", methods=["POST"])
def validar_lista_api():
    if "usuario_id" not in session or not session.get("is_admin"):
        return jsonify({"error": "Não autorizado"}), 401
    validador_id = session["usuario_id"]
    data = request.get_json()
    
    if not data or not data.get("data_envio") or not data.get("nome_usuario"):
        return jsonify({"error": "Dados incompletos para validação"}), 400
        
    data_envio_str = data["data_envio"]
    nome_usuario = data["nome_usuario"]
    
    if validar_lista(data_envio_str, nome_usuario, validador_id):
        return jsonify({"message": "Lista validada com sucesso!"}), 200
    else:
        return jsonify({"error": "Erro ao validar a lista."}), 500

@app.route("/api/exportar-lista", methods=["POST"])
def exportar_lista_api():
    if "usuario_id" not in session or not session.get("is_admin"):
        return jsonify({"error": "Não autorizado"}), 401
    data = request.get_json()
    
    if not data or not data.get("data_envio") or not data.get("nome_usuario"):
        return jsonify({"error": "Dados incompletos para exportação"}), 400
        
    data_envio_str = data["data_envio"]
    nome_usuario = data["nome_usuario"]
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM usuarios WHERE nome = ?", (nome_usuario,))
            usuario = cursor.fetchone()
            if not usuario:
                return jsonify({"error": "Usuário não encontrado"}), 404
            usuario_id = usuario["id"]
            
            cursor.execute("""
            SELECT p.ean, p.nome, p.cor, p.voltagem, p.modelo, p.quantidade, p.preco_medio, 
                   u_validador.nome as nome_validador, p.data_validacao, 
                   r.nome as nome_responsavel, p.responsavel_pin
            FROM produtos p 
            LEFT JOIN usuarios u_validador ON p.validador_id = u_validador.id
            LEFT JOIN responsaveis r ON p.responsavel_id = r.id
            WHERE p.usuario_id = ? AND p.data_envio = ? AND p.enviado = 1
            """, (usuario_id, data_envio_str))
            
            produtos_lista = [dict(row) for row in cursor.fetchall()]
            
        if not produtos_lista:
            return jsonify({"error": "Nenhum produto encontrado para esta lista/data de envio"}), 404

        df = pd.DataFrame(produtos_lista)
        # Renomear colunas para melhor clareza no Excel
        df.rename(columns={
            "ean": "EAN", "nome": "Nome do Produto", "cor": "Cor", "voltagem": "Voltagem",
            "modelo": "Modelo", "quantidade": "Quantidade", "preco_medio": "Preço Médio (ML)",
            "nome_validador": "Validado Por", "data_validacao": "Data Validação",
            "nome_responsavel": "Responsável Envio", "responsavel_pin": "PIN Envio"
        }, inplace=True)
        
        # Formatar data de validação
        if "Data Validação" in df.columns:
             df["Data Validação"] = df["Data Validação"].apply(lambda x: formatar_data_brasileira(x) if pd.notna(x) else "Não Validado")
        
        # Formatar preço médio
        if "Preço Médio (ML)" in df.columns:
            df["Preço Médio (ML)"] = df["Preço Médio (ML)"].apply(lambda x: f"R$ {x:.2f}".replace(".", ",") if pd.notna(x) else "N/A")

        # Preparar nome do arquivo
        data_envio_obj = datetime.fromisoformat(data_envio_str.replace("Z", "+00:00"))
        data_formatada = data_envio_obj.strftime("%Y%m%d_%H%M%S")
        nome_usuario_limpo = re.sub(r"\W+", "", nome_usuario) # Remover caracteres não alfanuméricos
        filename = f"lista_{nome_usuario_limpo}_{data_formatada}.xlsx"

        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Produtos")
        output.seek(0)
        
        return send_file(output, 
                         download_name=filename, 
                         as_attachment=True, 
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    except sqlite3.Error as e:
        print(f"Erro de banco de dados ao exportar lista: {e}")
        return jsonify({"error": "Erro interno do servidor ao exportar a lista (DB)"}), 500
    except Exception as e:
        print(f"Erro inesperado ao exportar lista: {e}")
        return jsonify({"error": "Erro interno do servidor ao exportar a lista"}), 500

# --- Rotas de Autorização Mercado Livre --- 

@app.route("/authorize_ml")
def authorize_ml():
    if "usuario_id" not in session:
        flash("Faça login para autorizar com o Mercado Livre.", "warning")
        return redirect(url_for("login"))

    # Gerar PKCE
    code_verifier = secrets.token_urlsafe(64)
    session["ml_code_verifier"] = code_verifier # Salvar na sessão
    
    hashed = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(hashed).decode("utf-8").replace("=", "")
    code_challenge_method = "S256"

    # Montar URL de autorização
    params = {
        "response_type": "code",
        "client_id": ML_CLIENT_ID,
        "redirect_uri": ML_REDIRECT_URI,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method
    }
    auth_url_with_params = f"{ML_AUTH_URL}?{requests.compat.urlencode(params)}"
    
    print(f"Redirecionando para: {auth_url_with_params}") # Log para debug
    return redirect(auth_url_with_params)

@app.route("/ml_callback")
def ml_callback():
    if "usuario_id" not in session:
        flash("Sessão inválida ou expirada.", "danger")
        return redirect(url_for("login"))

    usuario_id = session["usuario_id"]
    code = request.args.get("code")
    error = request.args.get("error")
    code_verifier = session.pop("ml_code_verifier", None) # Recuperar e remover da sessão

    if error:
        flash(f"Erro na autorização do Mercado Livre: {error}", "danger")
        return redirect(url_for("index"))

    if not code:
        flash("Código de autorização do Mercado Livre não recebido.", "danger")
        return redirect(url_for("index"))
        
    if not code_verifier:
        flash("Erro interno: Verificador PKCE não encontrado na sessão.", "danger")
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
    
    headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
    
    try:
        print("Enviando requisição para obter token...") # Log
        response = requests.post(ML_TOKEN_URL, data=token_payload, headers=headers)
        response.raise_for_status() # Lança exceção para erros HTTP (4xx ou 5xx)
        
        token_data = response.json()
        print("Token recebido:", token_data) # Log
        
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in")
        
        if not access_token or not refresh_token or expires_in is None:
             flash("Resposta inválida da API de tokens do Mercado Livre.", "danger")
             print("Erro: Dados de token ausentes na resposta.")
             return redirect(url_for("index"))

        # Salvar tokens no banco de dados
        if salvar_tokens_ml(usuario_id, access_token, refresh_token, expires_in):
            flash("Autorização com Mercado Livre concluída com sucesso!", "success")
        else:
            flash("Erro ao salvar informações de autorização no banco de dados.", "danger")
            
    except requests.exceptions.RequestException as e:
        flash(f"Erro ao comunicar com a API do Mercado Livre: {e}", "danger")
        print(f"Erro na requisição de token: {e}")
        if e.response is not None:
             print(f"Resposta da API: {e.response.status_code} - {e.response.text}")
    except Exception as e:
        flash(f"Ocorreu um erro inesperado durante a autorização: {e}", "danger")
        print(f"Erro inesperado no callback: {e}")

    return redirect(url_for("index"))


if __name__ == "__main__":
    # Não execute init_database() aqui se estiver usando Gunicorn/Waitress,
    # pois pode ser chamado múltiplas vezes. A chamada no início do script garante execução única.
    app.run(debug=True, host="0.0.0.0", port=5001) # Porta diferente para debug local
