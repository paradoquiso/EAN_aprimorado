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
# Importa a função de busca que agora usa client_credentials automaticamente
from src.mercado_livre import buscar_produto_por_ean as buscar_produto_online 
import re # Importar re para limpar nome de arquivo

app = Flask(__name__)
# É CRUCIAL usar uma chave secreta forte e, preferencialmente, de variável de ambiente
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "ean_app_secret_key_default_dev_only") 

# Configuração do banco de dados SQLite
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
            # Criar tabela usuarios se não existir (removidas colunas de token ML)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL UNIQUE,
                senha_hash TEXT NOT NULL,
                admin INTEGER DEFAULT 0
            );
            """)
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
            # Tenta converter de ISO format com ou sem Z
            data = datetime.fromisoformat(data.replace("Z", "+00:00"))
        except ValueError:
            try:
                 # Tenta converter de formato com microsegundos
                 data = datetime.strptime(data, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                 try:
                     # Tenta converter de formato sem microsegundos
                     data = datetime.strptime(data, "%Y-%m-%d %H:%M:%S")
                 except ValueError:
                     return data # Retorna a string original se não conseguir converter
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
            cursor.execute("SELECT id, quantidade FROM produtos WHERE ean = ? AND usuario_id = ? AND enviado = 0", (produto["ean"], usuario_id))
            existing = cursor.fetchone()
            timestamp_obj = produto.get("timestamp")
            timestamp_str = (timestamp_obj.astimezone(timezone.utc).isoformat() 
                             if isinstance(timestamp_obj, datetime) 
                             else datetime.now(timezone.utc).isoformat())
            preco_medio = produto.get("preco_medio")

            if existing:
                nova_quantidade = existing["quantidade"] + produto["quantidade"]
                cursor.execute("UPDATE produtos SET quantidade = ?, timestamp = ?, preco_medio = ? WHERE id = ?",
                               (nova_quantidade, timestamp_str, preco_medio, existing["id"]))
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
        return "erro_db"
    except Exception as e:
        print(f"Erro inesperado ao enviar lista: {e}")
        return "erro_inesperado"

def deletar_produto(produto_id, usuario_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM produtos WHERE id = ? AND usuario_id = ? AND enviado = 0", (produto_id, usuario_id))
            conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Erro ao deletar produto: {e}")
        return False

def validar_produto(produto_id, validador_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            data_validacao_str = datetime.now(timezone.utc).isoformat()
            cursor.execute("UPDATE produtos SET validado = 1, validador_id = ?, data_validacao = ? WHERE id = ? AND enviado = 1",
                           (validador_id, data_validacao_str, produto_id))
            conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Erro ao validar produto: {e}")
        return False

def desvalidar_produto(produto_id):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE produtos SET validado = 0, validador_id = NULL, data_validacao = NULL WHERE id = ? AND enviado = 1",
                           (produto_id,))
            conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Erro ao desvalidar produto: {e}")
        return False

# --- Rotas Flask ---
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
            if session["is_admin"]:
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("index"))
        else:
            flash("Nome de usuário ou senha inválidos.", "danger")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nome = request.form["nome"]
        senha = request.form["senha"]
        if registrar_usuario(nome, senha):
            flash("Usuário registrado com sucesso! Faça o login.", "success")
            return redirect(url_for("login"))
        else:
            flash("Nome de usuário já existe ou ocorreu um erro.", "danger")
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Você saiu da sua conta.", "info")
    return redirect(url_for("login"))

@app.route("/")
def index():
    if "usuario_id" not in session:
        return redirect(url_for("login"))
    
    usuario_id = session["usuario_id"]
    produtos = carregar_produtos_usuario(usuario_id, apenas_nao_enviados=True)
    responsaveis = obter_responsaveis()
    
    return render_template("index.html", produtos=produtos, responsaveis=responsaveis)

@app.route("/admin")
def admin_dashboard():
    if "usuario_id" not in session or not session.get("is_admin"):
        flash("Acesso não autorizado.", "danger")
        return redirect(url_for("login"))
    
    termo_pesquisa = request.args.get("q", "")
    if termo_pesquisa:
        listas_enviadas = pesquisar_produtos(termo_pesquisa)
    else:
        listas_enviadas = carregar_todas_listas_enviadas()
        
    # Agrupar por usuário e data de envio para exibição
    listas_agrupadas = {}
    for produto in listas_enviadas:
        chave = (produto["usuario_id"], produto["data_envio"])
        if chave not in listas_agrupadas:
            listas_agrupadas[chave] = {
                "usuario_nome": produto["nome_usuario"],
                "data_envio": produto["data_envio"],
                "responsavel_nome": produto["nome_responsavel"],
                "produtos": []
            }
        listas_agrupadas[chave]["produtos"].append(produto)
        
    return render_template("admin.html", listas_agrupadas=listas_agrupadas.values(), termo_pesquisa=termo_pesquisa)

@app.route("/buscar_ean", methods=["POST"])
def buscar_ean():
    if "usuario_id" not in session:
        return jsonify({"success": False, "message": "Usuário não logado."}), 401
        
    ean = request.json.get("ean")
    if not ean:
        return jsonify({"success": False, "message": "Código EAN não fornecido."}), 400

    # 1. Tenta buscar localmente primeiro (produtos não enviados do usuário)
    produto_local = buscar_produto_local(ean, session["usuario_id"])
    if produto_local:
        print(f"Produto {ean} encontrado localmente para usuário {session["usuario_id"]}")
        return jsonify({
            "success": True,
            "data": produto_local,
            "message": "Produto encontrado localmente.",
            "source": "local"
        })

    # 2. Se não encontrou localmente, busca online
    print(f"Produto {ean} não encontrado localmente. Buscando online...")
    resultado_online = buscar_produto_online(ean)
    return jsonify(resultado_online)

@app.route("/adicionar_produto", methods=["POST"])
def adicionar_produto():
    if "usuario_id" not in session:
        return jsonify({"success": False, "message": "Usuário não logado."}), 401

    dados = request.json
    ean = dados.get("ean")
    nome = dados.get("nome")
    quantidade_str = dados.get("quantidade", "1")
    preco_medio_str = dados.get("preco_medio")

    if not ean or not nome:
        return jsonify({"success": False, "message": "EAN e Nome são obrigatórios."}), 400

    try:
        quantidade = int(quantidade_str)
        if quantidade <= 0:
            raise ValueError("Quantidade deve ser positiva.")
    except (ValueError, TypeError):
        return jsonify({"success": False, "message": "Quantidade inválida."}), 400
        
    preco_medio = None
    if preco_medio_str:
        try:
            preco_medio = float(preco_medio_str)
        except (ValueError, TypeError):
            print(f"Aviso: Preço médio 
(Content truncated due to size limit. Use line ranges to read in chunks)
