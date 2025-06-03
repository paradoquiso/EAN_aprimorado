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
                
                # Tabela de produtos (adicionado campo preco_medio)
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
                    preco_medio DECIMAL(10, 2) NULL,
                    FOREIGN KEY (usuario_id) REFERENCES usuarios (id),
                    FOREIGN KEY (validador_id) REFERENCES usuarios (id),
                    FOREIGN KEY (responsavel_id) REFERENCES responsaveis (id)
                );
                """)
                
                # Verificar se a coluna preco_medio já existe, se não, adicioná-la
                try:
                    cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name='produtos' AND column_name='preco_medio';
                    """)
                    
                    if cursor.fetchone() is None:
                        cursor.execute("""
                        ALTER TABLE produtos ADD COLUMN preco_medio DECIMAL(10, 2) NULL;
                        """)
                        print("Coluna preco_medio adicionada à tabela produtos.")
                except Exception as e:
                    print(f"Erro ao verificar/adicionar coluna preco_medio: {e}")
                
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
                cursor.execute("SELECT COUNT(*) FROM responsaveis")
                resp_count = cursor.fetchone()[0]
                
                if resp_count == 0:
                    # Adicionar alguns responsáveis padrão para teste
                    responsaveis = [
                        ("Carlos", "1234"),
                        ("Ana", "5678"),
                        ("Pedro", "9012")
                    ]
                    
                    for nome, pin in responsaveis:
                        cursor.execute("INSERT INTO responsaveis (nome, pin) VALUES (%s, %s)", (nome, pin))
                
                conn.commit()
                print("Banco de dados inicializado com sucesso.")
    except Exception as e:
        print(f"Erro ao inicializar banco de dados: {e}")
        raise

def registrar_usuario(nome, senha):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                senha_hash = generate_password_hash(senha)
                cursor.execute('INSERT INTO usuarios (nome, senha_hash) VALUES (%s, %s)', (nome, senha_hash))
                conn.commit()
                return True
    except Exception as e:
        print(f"Erro ao registrar usuário: {e}")
        return False

def verificar_usuario(nome, senha):
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute('SELECT id, senha_hash, admin FROM usuarios WHERE nome = %s', (nome,))
                usuario = cursor.fetchone()
                
                if usuario and check_password_hash(usuario['senha_hash'], senha):
                    return {'id': usuario['id'], 'admin': usuario['admin']}
        return None
    except Exception as e:
        print(f"Erro ao verificar usuário: {e}")
        return None

def obter_nome_usuario(usuario_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT nome FROM usuarios WHERE id = %s', (usuario_id,))
                usuario = cursor.fetchone()
                return usuario[0] if usuario else None
    except Exception as e:
        print(f"Erro ao obter nome do usuário: {e}")
        return None

def carregar_produtos_usuario(usuario_id, apenas_nao_enviados=False):
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                if apenas_nao_enviados:
                    cursor.execute('SELECT * FROM produtos WHERE usuario_id = %s AND enviado = 0', (usuario_id,))
                else:
                    cursor.execute('SELECT * FROM produtos WHERE usuario_id = %s', (usuario_id,))
                
                produtos = cursor.fetchall()
                return [dict(produto) for produto in produtos]
    except Exception as e:
        print(f"Erro ao carregar produtos do usuário: {e}")
        return []

def carregar_todas_listas_enviadas():
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute('''
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
                ''')
                
                produtos = cursor.fetchall()
                return [dict(produto) for produto in produtos]
    except Exception as e:
        print(f"Erro ao carregar todas as listas enviadas: {e}")
        return []

def pesquisar_produtos(termo_pesquisa):
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute('''
                SELECT p.*, 
                       u.nome as nome_usuario,
                       v.nome as nome_validador,
                       r.nome as nome_responsavel
                FROM produtos p 
                JOIN usuarios u ON p.usuario_id = u.id 
                LEFT JOIN usuarios v ON p.validador_id = v.id
                LEFT JOIN responsaveis r ON p.responsavel_id = r.id
                WHERE p.enviado = 1 
                  AND (p.ean LIKE %s OR p.nome LIKE %s OR p.cor LIKE %s OR p.modelo LIKE %s)
                ORDER BY p.data_envio DESC
                ''', (f'%{termo_pesquisa}%', f'%{termo_pesquisa}%', f'%{termo_pesquisa}%', f'%{termo_pesquisa}%'))
                
                produtos = cursor.fetchall()
                return [dict(produto) for produto in produtos]
    except Exception as e:
        print(f"Erro ao pesquisar produtos: {e}")
        return []

def buscar_produto_local(ean, usuario_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute('SELECT * FROM produtos WHERE ean = %s AND usuario_id = %s AND enviado = 0', (ean, usuario_id))
                produto = cursor.fetchone()
                return dict(produto) if produto else None
    except Exception as e:
        print(f"Erro ao buscar produto local: {e}")
        return None

def salvar_produto(produto, usuario_id, preco_medio=None):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Verificar se o produto já existe na lista do usuário
                cursor.execute('SELECT * FROM produtos WHERE ean = %s AND usuario_id = %s AND enviado = 0', 
                            (produto['ean'], usuario_id))
                existing = cursor.fetchone()
                
                timestamp_obj = datetime.now()
                
                if existing:
                    # Se já existe, apenas atualiza a quantidade e timestamp
                    cursor.execute('''
                    UPDATE produtos 
                    SET quantidade = quantidade + %s, 
                        timestamp = %s 
                    WHERE ean = %s AND usuario_id = %s AND enviado = 0
                    ''', (produto['quantidade'], timestamp_obj, produto['ean'], usuario_id))
                else:
                    # Se não existe, insere novo produto com preço médio
                    cursor.execute('''
                    INSERT INTO produtos (ean, nome, cor, voltagem, modelo, quantidade, usuario_id, timestamp, enviado, preco_medio)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 0, %s)
                    ''', (
                        produto['ean'], 
                        produto['nome'], 
                        produto.get('cor'), 
                        produto.get('voltagem'), 
                        produto.get('modelo'), 
                        produto['quantidade'], 
                        usuario_id,
                        timestamp_obj,
                        preco_medio
                    ))
                
                conn.commit()
    except Exception as e:
        print(f"Erro ao salvar produto: {e}")
        raise

def enviar_lista_produtos(usuario_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                data_envio = datetime.now()
                
                cursor.execute('''
                UPDATE produtos 
                SET enviado = 1, 
                    data_envio = %s 
                WHERE usuario_id = %s AND enviado = 0
                ''', (data_envio, usuario_id))
                
                conn.commit()
                return data_envio
    except Exception as e:
        print(f"Erro ao enviar lista de produtos: {e}")
        raise

def validar_lista(data_envio, nome_usuario, validador_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Buscar o ID do usuário pelo nome
                cursor.execute('SELECT id FROM usuarios WHERE nome = %s', (nome_usuario,))
                usuario = cursor.fetchone()
                
                if not usuario:
                    return False
                
                usuario_id = usuario[0]
                data_validacao = datetime.now()
                
                cursor.execute('''
                UPDATE produtos 
                SET validado = 1, 
                    validador_id = %s,
                    data_validacao = %s 
                WHERE usuario_id = %s AND data_envio = %s AND enviado = 1
                ''', (validador_id, data_validacao, usuario_id, data_envio))
                
                conn.commit()
                return True
    except Exception as e:
        print(f"Erro ao validar lista: {e}")
        return False

def atribuir_responsavel(data_envio, nome_usuario, responsavel_id, responsavel_pin):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Buscar o ID do usuário pelo nome
                cursor.execute('SELECT id FROM usuarios WHERE nome = %s', (nome_usuario,))
                usuario = cursor.fetchone()
                
                if not usuario:
                    return False
                
                usuario_id = usuario[0]
                
                # Verificar se o PIN do responsável está correto
                cursor.execute('SELECT pin FROM responsaveis WHERE id = %s', (responsavel_id,))
                resp = cursor.fetchone()
                
                if not resp or resp[0] != responsavel_pin:
                    return False
                
                cursor.execute('''
                UPDATE produtos 
                SET responsavel_id = %s,
                    responsavel_pin = %s
                WHERE usuario_id = %s AND data_envio = %s AND enviado = 1
                ''', (responsavel_id, responsavel_pin, usuario_id, data_envio))
                
                conn.commit()
                return True
    except Exception as e:
        print(f"Erro ao atribuir responsável: {e}")
        return False

def excluir_produto(produto_id, usuario_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('DELETE FROM produtos WHERE id = %s AND usuario_id = %s AND enviado = 0', 
                            (produto_id, usuario_id))
                conn.commit()
    except Exception as e:
        print(f"Erro ao excluir produto: {e}")
        raise

def obter_responsaveis():
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute('SELECT id, nome FROM responsaveis ORDER BY nome')
                responsaveis = cursor.fetchall()
                return [dict(resp) for resp in responsaveis]
    except Exception as e:
        print(f"Erro ao obter responsáveis: {e}")
        return []

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        nome = request.form.get('nome')
        senha = request.form.get('senha')
        
        usuario = verificar_usuario(nome, senha)
        if usuario:
            session['user_id'] = usuario['id']
            session['usuario_nome'] = nome
            session['admin'] = usuario['admin']
            
            if usuario['admin']:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('index'))
        else:
            flash('Nome de usuário ou senha incorretos')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        nome = request.form.get('nome')
        senha = request.form.get('senha')
        
        if registrar_usuario(nome, senha):
            flash('Usuário registrado com sucesso! Faça login para continuar.')
            return redirect(url_for('login'))
        else:
            flash('Nome de usuário já existe')
    
    return render_template('registro.html')

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    produtos = carregar_produtos_usuario(session['user_id'], apenas_nao_enviados=True)
    return render_template('index.html', produtos=produtos)

@app.route('/admin')
def admin_panel():
    if 'user_id' not in session or not session.get('admin'):
        return redirect(url_for('login'))
    
    termo_pesquisa = request.args.get('pesquisa', '')
    
    if termo_pesquisa:
        produtos_encontrados = pesquisar_produtos(termo_pesquisa)
        listas_agrupadas = {}
        for produto in produtos_encontrados:
            chave = (produto['data_envio'], produto['nome_usuario'])
            if chave not in listas_agrupadas:
                listas_agrupadas[chave] = {
                    'produtos': [],
                    'validado': produto.get('validado', 0),
                    'nome_validador': produto.get('nome_validador', None),
                    'data_validacao': produto.get('data_validacao', None),
                    'responsavel_id': produto.get('responsavel_id', None),
                    'nome_responsavel': produto.get('nome_responsavel', None)
                }
            listas_agrupadas[chave]['produtos'].append(produto)
        
        responsaveis = obter_responsaveis()
        return render_template('admin.html', listas_agrupadas=listas_agrupadas, termo_pesquisa=termo_pesquisa, responsaveis=responsaveis)
    else:
        listas_enviadas = carregar_todas_listas_enviadas()
        listas_agrupadas = {}
        for produto in listas_enviadas:
            chave = (produto['data_envio'], produto['nome_usuario'])
            if chave not in listas_agrupadas:
                listas_agrupadas[chave] = {
                    'produtos': [],
                    'validado': produto.get('validado', 0),
                    'nome_validador': produto.get('nome_validador', None),
                    'data_validacao': produto.get('data_validacao', None),
                    'responsavel_id': produto.get('responsavel_id', None),
                    'nome_responsavel': produto.get('nome_responsavel', None)
                }
            listas_agrupadas[chave]['produtos'].append(produto)
        
        responsaveis = obter_responsaveis()
        return render_template('admin.html', listas_agrupadas=listas_agrupadas, termo_pesquisa='', responsaveis=responsaveis)

@app.route('/api/buscar-produto', methods=['GET'])
def buscar_produto():
    if 'user_id' not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    ean = request.args.get('ean')
    if not ean:
        return jsonify({"error": "EAN não fornecido"}), 400
    
    # Primeiro, verificar se o produto já existe no banco de dados local
    produto_local = buscar_produto_local(ean, session['user_id'])
    if produto_local:
        return jsonify({
            "ean": produto_local['ean'],
            "nome": produto_local['nome'],
            "cor": produto_local['cor'] or '',
            "voltagem": produto_local['voltagem'] or '',
            "modelo": produto_local['modelo'] or '',
            "quantidade": produto_local['quantidade'],
            "preco_medio": float(produto_local['preco_medio']) if produto_local['preco_medio'] is not None else None,
            "message": "Produto encontrado no banco de dados local."
        })
    
    # Se não existir localmente, buscar online
    try:
        # Tentar buscar no Mercado Livre
        from src.mercado_livre import buscar_produto_por_ean
        produto_ml = buscar_produto_por_ean(ean)
        
        if produto_ml and produto_ml.get('success'):
            data = produto_ml.get('data', {})
            return jsonify({
                "ean": ean,
                "nome": data.get('nome', f"Produto {ean}"),
                "cor": data.get('cor', ''),
                "voltagem": data.get('voltagem', ''),
                "modelo": data.get('modelo', ''),
                "quantidade": 1,
                "preco_medio": data.get('preco_medio'),
                "message": "Produto encontrado no Mercado Livre."
            })
    except Exception as e:
        print(f"Erro ao buscar no Mercado Livre: {str(e)}")
    
    # Se não encontrou no Mercado Livre, retornar dados básicos
    return jsonify({
        "ean": ean,
        "nome": f"Produto {ean}",
        "cor": "",
        "voltagem": "",
        "modelo": "",
        "quantidade": 1,
        "preco_medio": None,
        "message": "Produto não encontrado. Preencha os dados manualmente."
    })

@app.route('/api/adicionar-produto', methods=['POST'])
def adicionar_produto():
    if 'user_id' not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    data = request.json
    produto = {
        'ean': data.get('ean'),
        'nome': data.get('nome'),
        'cor': data.get('cor'),
        'voltagem': data.get('voltagem'),
        'modelo': data.get('modelo'),
        'quantidade': int(data.get('quantidade', 1))
    }
    
    if not produto['ean'] or not produto['nome']:
        return jsonify({"error": "EAN e Nome são obrigatórios"}), 400
    
    try:
        # Obter o preço médio do JSON, se disponível
        preco_medio = data.get('preco_medio')
        if preco_medio is not None:
            try:
                preco_medio = float(preco_medio)
            except (ValueError, TypeError):
                preco_medio = None
        
        salvar_produto(produto, session['user_id'], preco_medio)
        return jsonify({"success": True, "message": "Produto adicionado/atualizado com sucesso"})
    except Exception as e:
        print(f"Erro ao adicionar produto: {str(e)}")
        return jsonify({"error": f"Erro ao adicionar produto: {str(e)}"}), 500

@app.route('/api/exportar-excel')
def exportar_excel():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    produtos = carregar_produtos_usuario(session['user_id'], apenas_nao_enviados=True)
    
    if not produtos:
        flash("Nenhum produto na lista para exportar.")
        return redirect(url_for('index'))
        
    df = pd.DataFrame(produtos)
    # Selecionar e reordenar colunas, incluindo preco_medio
    df = df[["ean", "nome", "cor", "voltagem", "modelo", "quantidade", "preco_medio", "timestamp"]]
    
    output = io.BytesIO()
    writer = pd.ExcelWriter(output, engine="openpyxl")
    df.to_excel(writer, index=False, sheet_name="Produtos")
    writer.close()
    output.seek(0)
    
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    usuario_nome = session.get("usuario_nome", "usuario")
    nome_arquivo = f"produtos_ean_{usuario_nome}_{timestamp_str}.xlsx"
    
    return send_file(output, 
                     download_name=nome_arquivo, 
                     as_attachment=True,
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

@app.route('/api/excluir-produto/<int:produto_id>', methods=['POST'])
def excluir_produto_route(produto_id):
    if 'user_id' not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    try:
        excluir_produto(produto_id, session['user_id'])
        return jsonify({"success": True, "message": "Produto excluído com sucesso"})
    except Exception as e:
        print(f"Erro ao excluir produto: {str(e)}")
        return jsonify({"error": f"Erro ao excluir produto: {str(e)}"}), 500

@app.route('/api/enviar-lista', methods=['POST'])
def enviar_lista():
    if 'user_id' not in session:
        return jsonify({"error": "Não autorizado"}), 401
    
    produtos = carregar_produtos_usuario(session['user_id'], apenas_nao_enviados=True)
    
    if not produtos:
        return jsonify({"error": "Nenhum produto na lista para enviar"}), 400
    
    try:
        data_envio = enviar_lista_produtos(session['user_id'])
        return jsonify({
            "success": True, 
            "message": "Lista enviada com sucesso", 
            "data_envio": data_envio.strftime("%Y-%m-%d %H:%M:%S")
        })
    except Exception as e:
        print(f"Erro ao enviar lista: {str(e)}")
        return jsonify({"error": f"Erro ao enviar lista: {str(e)}"}), 500

@app.route('/api/validar-lista', methods=['POST'])
def validar_lista_route():
    if 'user_id' not in session or not session.get('admin'):
        return jsonify({"error": "Não autorizado"}), 401
    
    data = request.json
    data_envio = data.get('data_envio')
    nome_usuario = data.get('nome_usuario')
    
    if not data_envio or not nome_usuario:
        return jsonify({"error": "Dados incompletos"}), 400
    
    try:
        if validar_lista(data_envio, nome_usuario, session['user_id']):
            return jsonify({"success": True, "message": "Lista validada com sucesso"})
        else:
            return jsonify({"error": "Falha ao validar lista"}), 400
    except Exception as e:
        print(f"Erro ao validar lista: {str(e)}")
        return jsonify({"error": f"Erro ao validar lista: {str(e)}"}), 500

@app.route('/api/atribuir-responsavel', methods=['POST'])
def atribuir_responsavel_route():
    if 'user_id' not in session or not session.get('admin'):
        return jsonify({"error": "Não autorizado"}), 401
    
    data = request.json
    data_envio = data.get('data_envio')
    nome_usuario = data.get('nome_usuario')
    responsavel_id = data.get('responsavel_id')
    responsavel_pin = data.get('responsavel_pin')
    
    if not data_envio or not nome_usuario or not responsavel_id or not responsavel_pin:
        return jsonify({"error": "Dados incompletos"}), 400
    
    try:
        if atribuir_responsavel(data_envio, nome_usuario, responsavel_id, responsavel_pin):
            return jsonify({"success": True, "message": "Responsável atribuído com sucesso"})
        else:
            return jsonify({"error": "Falha ao atribuir responsável. Verifique o PIN."}), 400
    except Exception as e:
        print(f"Erro ao atribuir responsável: {str(e)}")
        return jsonify({"error": f"Erro ao atribuir responsável: {str(e)}"}), 500

# Inicializar o banco de dados na primeira execução
if __name__ == '__main__':
    init_database()
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)), debug=False)
