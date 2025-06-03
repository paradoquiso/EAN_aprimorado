import sys
import os
# import sqlite3 # Removido
import psycopg2
import psycopg2.extras # Adicionado para DictCursor
from datetime import datetime
import io
import requests
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
import pandas as pd
import json
from werkzeug.security import generate_password_hash, check_password_hash
from src.utils import formatar_data_brasileira  # Importando a função de formatação de data

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "ean_app_secret_key_default") # Usar variável de ambiente para secret key

# Registrar filtro Jinja2 para formatação de data brasileira
@app.template_filter('data_brasileira')
def data_brasileira_filter(data):
    return formatar_data_brasileira(data)

# Configuração do banco de dados PostgreSQL a partir da variável de ambiente
DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    print("Erro: Variável de ambiente DATABASE_URL não definida.")
    # Em um ambiente de produção, você pode querer lançar uma exceção ou sair
    # Para desenvolvimento local, pode-se definir um valor padrão, mas não é recomendado para produção.
    # DATABASE_URL = "postgresql://user:password@host:port/database" # Exemplo
    sys.exit(1) # Sair se a URL do banco não estiver configurada

# Função auxiliar para obter conexão
def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

# Inicializar o banco de dados (adaptado para PostgreSQL)
def init_database():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Tabela de usuários
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS usuarios (
                    id SERIAL PRIMARY KEY,
                    nome TEXT NOT NULL UNIQUE,
                    senha_hash TEXT NOT NULL,
                    admin INTEGER DEFAULT 0
                );
                """)
                
                # Tabela de responsáveis com PIN
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS responsaveis (
                    id SERIAL PRIMARY KEY,
                    nome TEXT NOT NULL UNIQUE,
                    pin TEXT NOT NULL
                );
                """)
                
                # Tabela de produtos
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS produtos (
                    id SERIAL PRIMARY KEY,
                    ean TEXT NOT NULL,
                    nome TEXT NOT NULL,
                    cor TEXT,
                    voltagem TEXT,
                    modelo TEXT,
                    quantidade INTEGER NOT NULL,
                    usuario_id INTEGER NOT NULL,
                    timestamp TIMESTAMP,
                    enviado INTEGER DEFAULT 0,
                    data_envio TIMESTAMP,
                    validado INTEGER DEFAULT 0,
                    validador_id INTEGER,
                    data_validacao TIMESTAMP,
                    responsavel_id INTEGER,
                    responsavel_pin TEXT,
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
                        cursor.execute("INSERT INTO usuarios (nome, senha_hash, admin) VALUES (%s, %s, %s)", 
                                      ("admin", admin_hash, 1))
                
                # Inicializar responsáveis com PINs
                inicializar_responsaveis()
                
        print("Banco de dados inicializado com sucesso.")
    except psycopg2.Error as e:
        print(f"Erro ao inicializar o banco de dados: {e}")
        # Considerar logar o erro ou tratá-lo de forma mais robusta

# Inicializar responsáveis com PINs
def inicializar_responsaveis():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
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
                    
                    for nome, pin in responsaveis:
                        cursor.execute("INSERT INTO responsaveis (nome, pin) VALUES (%s, %s)", (nome, pin))
                    
                    print(f"Responsáveis inicializados: {len(responsaveis)}")
    except psycopg2.Error as e:
        print(f"Erro ao inicializar responsáveis: {e}")
        conn.rollback()

# Obter todos os responsáveis
def obter_responsaveis():
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute("SELECT id, nome FROM responsaveis ORDER BY nome")
                responsaveis = [dict(row) for row in cursor.fetchall()]
        return responsaveis
    except psycopg2.Error as e:
        print(f"Erro ao obter responsáveis: {e}")
        return []

# Verificar PIN do responsável
def verificar_pin_responsavel(responsavel_id, pin):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT pin FROM responsaveis WHERE id = %s", (responsavel_id,))
                resultado = cursor.fetchone()
                
                if resultado and resultado[0] == pin:
                    return True
                return False
    except psycopg2.Error as e:
        print(f"Erro ao verificar PIN do responsável: {e}")
        return False

# Obter nome do responsável
def obter_nome_responsavel(responsavel_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT nome FROM responsaveis WHERE id = %s", (responsavel_id,))
                resultado = cursor.fetchone()
                
                if resultado:
                    return resultado[0]
                return None
    except psycopg2.Error as e:
        print(f"Erro ao obter nome do responsável: {e}")
        return None

# Funções de autenticação (adaptadas para PostgreSQL)
def registrar_usuario(nome, senha):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                senha_hash = generate_password_hash(senha)
                cursor.execute("INSERT INTO usuarios (nome, senha_hash) VALUES (%s, %s)", (nome, senha_hash))
        return True
    except psycopg2.errors.UniqueViolation:
        # Nome de usuário já existe
        return False
    except psycopg2.Error as e:
        print(f"Erro ao registrar usuário: {e}")
        return False

def verificar_usuario(nome, senha):
    try:
        with get_db_connection() as conn:
            # Usar DictCursor para acessar colunas por nome
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute("SELECT id, senha_hash, admin FROM usuarios WHERE nome = %s", (nome,))
                usuario = cursor.fetchone()
        
        if usuario and check_password_hash(usuario["senha_hash"], senha):
            # Retornar como dicionário
            return {"id": usuario["id"], "admin": usuario["admin"]}
        return None
    except psycopg2.Error as e:
        print(f"Erro ao verificar usuário: {e}")
        return None

def obter_nome_usuario(usuario_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT nome FROM usuarios WHERE id = %s", (usuario_id,))
                usuario = cursor.fetchone()
        return usuario[0] if usuario else None
    except psycopg2.Error as e:
        print(f"Erro ao obter nome do usuário: {e}")
        return None

# Funções de produtos (adaptadas para PostgreSQL)
def carregar_produtos_usuario(usuario_id, apenas_nao_enviados=False):
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                if apenas_nao_enviados:
                    cursor.execute("SELECT * FROM produtos WHERE usuario_id = %s AND enviado = 0 ORDER BY timestamp DESC", (usuario_id,))
                else:
                    cursor.execute("SELECT * FROM produtos WHERE usuario_id = %s ORDER BY timestamp DESC", (usuario_id,))
                # Converter DictRow para dict
                produtos = [dict(row) for row in cursor.fetchall()]
        return produtos
    except psycopg2.Error as e:
        print(f"Erro ao carregar produtos do usuário: {e}")
        return []

def carregar_todas_listas_enviadas():
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                # Buscar produtos enviados junto com o nome do usuário, do validador e do responsável (se houver)
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
                print(f"Produtos enviados encontrados: {len(produtos)}")
                if len(produtos) > 0:
                    print(f"Exemplo do primeiro produto: {produtos[0]}")
                    
        return produtos
    except psycopg2.Error as e:
        print(f"Erro ao carregar todas as listas enviadas: {e}")
        return []

def pesquisar_produtos(termo_pesquisa):
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                # Buscar produtos que correspondem ao termo de pesquisa (EAN ou palavra na descrição)
                # Usar ILIKE para busca case-insensitive no PostgreSQL
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
                  AND (p.ean ILIKE %s OR p.nome ILIKE %s OR p.cor ILIKE %s OR p.modelo ILIKE %s)
                ORDER BY p.data_envio DESC
                """, (termo_like, termo_like, termo_like, termo_like))
                produtos = [dict(row) for row in cursor.fetchall()]
        return produtos
    except psycopg2.Error as e:
        print(f"Erro ao pesquisar produtos: {e}")
        return []

def buscar_produto_local(ean, usuario_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute("SELECT * FROM produtos WHERE ean = %s AND usuario_id = %s AND enviado = 0", (ean, usuario_id))
                produto = cursor.fetchone()
        return dict(produto) if produto else None
    except psycopg2.Error as e:
        print(f"Erro ao buscar produto local: {e}")
        return None

def salvar_produto(produto, usuario_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Verificar se o produto já existe para este usuário e não foi enviado
                cursor.execute("SELECT id FROM produtos WHERE ean = %s AND usuario_id = %s AND enviado = 0", 
                              (produto["ean"], usuario_id))
                existing = cursor.fetchone()
                
                # Garantir que timestamp seja um objeto datetime
                timestamp_obj = produto.get("timestamp")
                if isinstance(timestamp_obj, str):
                    try:
                        timestamp_obj = datetime.strptime(timestamp_obj, "%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        timestamp_obj = datetime.now() # Fallback
                elif not isinstance(timestamp_obj, datetime):
                     timestamp_obj = datetime.now()

                if existing:
                    # Atualizar quantidade
                    cursor.execute("""
                    UPDATE produtos 
                    SET quantidade = quantidade + %s, 
                        timestamp = %s 
                    WHERE ean = %s AND usuario_id = %s AND enviado = 0
                    """, (produto["quantidade"], timestamp_obj, produto["ean"], usuario_id))
                else:
                    # Inserir novo produto
                    cursor.execute("""
                    INSERT INTO produtos (ean, nome, cor, voltagem, modelo, quantidade, usuario_id, timestamp, enviado)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 0)
                    """, (
                        produto["ean"], 
                        produto["nome"], 
                        produto.get("cor"), # Usar .get para campos opcionais
                        produto.get("voltagem"), 
                        produto.get("modelo"), 
                        produto["quantidade"], 
                        usuario_id,
                        timestamp_obj
                    ))
        return True
    except psycopg2.Error as e:
        print(f"Erro ao salvar produto: {e}")
        conn.rollback() # Desfazer transação em caso de erro
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
            with conn.cursor() as cursor:
                data_envio = datetime.now()
                # Marcar todos os produtos não enviados como enviados
                cursor.execute("""
                UPDATE produtos 
                SET enviado = 1, 
                    data_envio = %s,
                    responsavel_id = %s,
                    responsavel_pin = %s
                WHERE usuario_id = %s AND enviado = 0
                """, (data_envio, responsavel_id, pin, usuario_id))
                
                # Verificar quantas linhas foram afetadas
                affected_rows = cursor.rowcount
                print(f"Produtos marcados como enviados: {affected_rows}")
                
        return data_envio
    except psycopg2.Error as e:
        print(f"Erro ao enviar lista de produtos: {e}")
        conn.rollback()
        return None

def validar_lista(data_envio, nome_usuario, validador_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Obter o ID do usuário pelo nome
                cursor.execute("SELECT id FROM usuarios WHERE nome = %s", (nome_usuario,))
                usuario = cursor.fetchone()
                
                if not usuario:
                    print(f"Usuário não encontrado: {nome_usuario}")
                    return False
                
                usuario_id = usuario[0]
                data_validacao = datetime.now()
                
                # Modificação: Usar uma comparação mais flexível para data_envio
                # Converter data_envio para string se for datetime
                if isinstance(data_envio, datetime):
                    data_envio_str = data_envio.strftime("%Y-%m-%d %H:%M")
                else:
                    # Se já for string, usar como está
                    data_envio_str = data_envio
                
                # Extrair apenas a parte da data sem segundos/milissegundos para comparação
                # Isso permite que "2025-05-30 19:41" corresponda a "2025-05-30 19:41:23.456789"
                print(f"Validando lista com data_envio aproximada: {data_envio_str}")
                
                # Usar LIKE para comparar apenas a parte da data sem segundos
                cursor.execute("""
                UPDATE produtos 
                SET validado = 1, 
                    validador_id = %s,
                    data_validacao = %s
                WHERE usuario_id = %s AND data_envio::text LIKE %s
                """, (validador_id, data_validacao, usuario_id, f"{data_envio_str}%"))
                
                # Verificar quantas linhas foram afetadas
                affected_rows = cursor.rowcount
                print(f"Produtos marcados como validados: {affected_rows}")
                
                if affected_rows == 0:
                    # Se nenhuma linha foi afetada, tentar uma abordagem ainda mais flexível
                    # Extrair apenas a data (sem hora)
                    if len(data_envio_str) >= 10:
                        data_apenas = data_envio_str[:10]  # YYYY-MM-DD
                        print(f"Tentando validação apenas com a data: {data_apenas}")
                        
                        cursor.execute("""
                        UPDATE produtos 
                        SET validado = 1, 
                            validador_id = %s,
                            data_validacao = %s
                        WHERE usuario_id = %s AND data_envio::text LIKE %s
                        """, (validador_id, data_validacao, usuario_id, f"{data_apenas}%"))
                        
                        affected_rows = cursor.rowcount
                        print(f"Produtos marcados como validados (segunda tentativa): {affected_rows}")
                
        return affected_rows > 0
    except psycopg2.Error as e:
        print(f"Erro ao validar lista: {e}")
        conn.rollback()
        return False
    except Exception as e:
        print(f"Erro inesperado ao validar lista: {e}")
        print(f"Tipo de data_envio: {type(data_envio)}, Valor: {data_envio}")
        conn.rollback()
        return False

def excluir_produto(produto_id, usuario_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Verificar se o produto pertence ao usuário e não foi enviado
                cursor.execute("SELECT id FROM produtos WHERE id = %s AND usuario_id = %s AND enviado = 0", 
                              (produto_id, usuario_id))
                produto = cursor.fetchone()
                
                if not produto:
                    return False
                
                # Excluir o produto
                cursor.execute("DELETE FROM produtos WHERE id = %s", (produto_id,))
                
        return True
    except psycopg2.Error as e:
        print(f"Erro ao excluir produto: {e}")
        conn.rollback()
        return False

# Importar função de busca do Mercado Livre
from src.mercado_livre import buscar_produto_por_ean as buscar_produto_online

# Rotas da aplicação
@app.route("/")
def index():
    if "usuario_id" not in session:
        return redirect(url_for("login"))
    
    produtos = carregar_produtos_usuario(session["usuario_id"], apenas_nao_enviados=True)
    return render_template("index.html", produtos=produtos)

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
    return redirect(url_for("login"))

@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nome = request.form.get("nome")
        senha = request.form.get("senha")
        
        if registrar_usuario(nome, senha):
            flash("Usuário registrado com sucesso! Faça login.")
            return redirect(url_for("login"))
        else:
            flash("Erro ao registrar usuário. Nome de usuário já existe.")
    
    return render_template("registro.html")

@app.route("/admin")
def admin():
    if "usuario_id" not in session or not session.get("admin"):
        return redirect(url_for("login"))
    
    termo_pesquisa = request.args.get("pesquisa", "")
    
    # Dicionário para agrupar produtos por data de envio e usuário
    listas_agrupadas = {}
    
    if termo_pesquisa:
        produtos_encontrados = pesquisar_produtos(termo_pesquisa)
        print(f"Produtos encontrados na pesquisa: {len(produtos_encontrados)}")
        
        # Agrupar produtos encontrados
        for produto in produtos_encontrados:
            # Usar data_envio e nome_usuario como chave
            # Tratar data_envio nula (caso ocorra)
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
        print(f"Total de listas enviadas carregadas: {len(listas_enviadas)}")
        
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
    
    print(f"Número de listas agrupadas: {len(listas_agrupadas)}")
    
    # Não converter para listas_ordenadas, manter como listas_agrupadas para o template
    return render_template("admin.html", listas_agrupadas=listas_agrupadas, termo_pesquisa=termo_pesquisa)

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
        return jsonify({
            "ean": produto_local["ean"],
            "nome": produto_local["nome"],
            "cor": produto_local.get("cor", ""),
            "voltagem": produto_local.get("voltagem", ""),
            "modelo": produto_local.get("modelo", ""),
            "quantidade": produto_local["quantidade"],
            "message": "Produto já existe na sua lista atual."
        }), 200 # OK, mas informa que já existe
    
    # Se não existir localmente, buscar online
    resultado = buscar_produto_online(ean)
    
    # A função buscar_produto_online já retorna um dict com 'success' e 'data'
    # Garantir que 'quantidade' seja incluída para o frontend
    if resultado["success"]:
         produto_data = resultado["data"]
         produto_data["ean"] = ean # Garantir que EAN esteja presente
         produto_data["quantidade"] = 1 # Quantidade padrão para novo produto
         return jsonify({
             **produto_data, # Desempacota os dados do produto
             "message": resultado.get("message", "")
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
            "message": resultado.get("message", "Falha ao buscar produto online. Preencha manualmente.")
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
        except ValueError:
            produto["quantidade"] = 1
        
        # Adicionar timestamp atual
        produto["timestamp"] = datetime.now()
        
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
        return jsonify({"success": True, "message": "Produto excluído com sucesso"}), 200
    else:
        return jsonify({"error": "Erro ao excluir produto"}), 500

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
        except ValueError:
            return jsonify({"error": "ID do responsável inválido"}), 400
        
        data_envio = enviar_lista_produtos(session["usuario_id"], responsavel_id, pin)
        
        if data_envio:
            # Formatar data para padrão brasileiro
            data_envio_formatada = formatar_data_brasileira(data_envio)
            return jsonify({
                "success": True, 
                "message": "Lista enviada com sucesso", 
                "data_envio": data_envio_formatada
            }), 200
        else:
            return jsonify({"error": "Erro ao enviar lista ou PIN inválido"}), 400
    except Exception as e:
        print(f"Erro ao enviar lista de produtos: {e}")
        return jsonify({"error": f"Erro ao processar requisição: {str(e)}"}), 500

@app.route("/api/validar-lista", methods=["POST"])
def validar_lista_api():
    if "usuario_id" not in session or not session.get("admin"):
        return jsonify({"error": "Não autorizado"}), 401
    
    try:
        data = request.json
        data_envio = data.get("data_envio")
        nome_usuario = data.get("nome_usuario")
        
        print(f"Recebida solicitação para validar lista: data_envio={data_envio}, nome_usuario={nome_usuario}")
        
        if not data_envio or not nome_usuario:
            return jsonify({"error": "Dados incompletos"}), 400
        
        if validar_lista(data_envio, nome_usuario, session["usuario_id"]):
            return jsonify({"success": True, "message": "Lista validada com sucesso"}), 200
        else:
            return jsonify({"error": "Erro ao validar lista. Verifique se a lista existe e não foi validada anteriormente."}), 500
    except Exception as e:
        print(f"Erro ao validar lista: {e}")
        return jsonify({"error": f"Erro ao processar requisição: {str(e)}"}), 500

@app.route("/api/export", methods=["GET"])
def export_produtos():
    if "usuario_id" not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    try:
        # Carregar produtos não enviados do usuário
        produtos = carregar_produtos_usuario(session["usuario_id"], apenas_nao_enviados=True)
        
        if not produtos:
            return jsonify({"error": "Não há produtos para exportar"}), 404
        
        # Criar DataFrame com os produtos
        df = pd.DataFrame(produtos)
        
        # Selecionar apenas as colunas desejadas
        colunas = ["ean", "nome", "cor", "voltagem", "modelo", "quantidade"]
        df = df[colunas]
        
        # Criar buffer para o arquivo Excel
        output = io.BytesIO()
        
        # Escrever DataFrame para Excel
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Produtos")
        
        # Preparar o arquivo para download
        output.seek(0)
        
        # Nome do arquivo com timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"produtos_{timestamp}.xlsx"
        
        return send_file(
            output,
            as_attachment=True,
            download_name=filename,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    except Exception as e:
        print(f"Erro ao exportar produtos: {e}")
        return jsonify({"error": f"Erro ao exportar produtos: {str(e)}"}), 500

# Inicializar o banco de dados ao iniciar a aplicação
init_database()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
