import sys
import os
import psycopg2
import psycopg2.extras
from datetime import datetime
import io
import requests
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session, flash
import pandas as pd
import json
from werkzeug.security import generate_password_hash, check_password_hash
from src.utils import formatar_data_brasileira

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "ean_app_secret_key_default")

# Registrar filtro Jinja2 para formatação de data brasileira
@app.template_filter('data_brasileira')
def data_brasileira_filter(data):
    return formatar_data_brasileira(data)

# Configuração do banco de dados PostgreSQL com fallback
DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    print("Aviso: Variável de ambiente DATABASE_URL não definida.")
    print("Para produção no Render.com, configure a variável DATABASE_URL.")
    # Fallback para desenvolvimento local (não recomendado para produção)
    DATABASE_URL = "postgresql://localhost/ean_database"
    print(f"Usando DATABASE_URL padrão: {DATABASE_URL}")

# Função auxiliar para obter conexão com tratamento de erro
def get_db_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except psycopg2.Error as e:
        print(f"Erro ao conectar com o banco de dados: {e}")
        print("Verifique se:")
        print("1. A variável DATABASE_URL está configurada corretamente")
        print("2. O banco de dados PostgreSQL está acessível")
        print("3. As credenciais estão corretas")
        raise

# Inicializar o banco de dados com tratamento de erro robusto
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
                );""")
                
                # Tabela de responsáveis com PIN
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS responsaveis (
                    id SERIAL PRIMARY KEY,
                    nome TEXT NOT NULL UNIQUE,
                    pin TEXT NOT NULL
                );""")
                
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
                    preco_medio DECIMAL(10,2),
                    data_cadastro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    usuario_id INTEGER,
                    enviado INTEGER DEFAULT 0,
                    data_envio TIMESTAMP,
                    responsavel_id INTEGER,
                    FOREIGN KEY (usuario_id) REFERENCES usuarios (id),
                    FOREIGN KEY (responsavel_id) REFERENCES responsaveis (id)
                );""")
                
                # Criar usuário admin padrão se não existir
                cursor.execute("SELECT COUNT(*) FROM usuarios WHERE nome = 'admin'")
                if cursor.fetchone()[0] == 0:
                    admin_hash = generate_password_hash('admin')
                    cursor.execute(
                        "INSERT INTO usuarios (nome, senha_hash, admin) VALUES (%s, %s, %s)",
                        ('admin', admin_hash, 1)
                    )
                    print("Usuário administrador criado: admin/admin")
                
                conn.commit()
                print("Banco de dados inicializado com sucesso")
                
    except Exception as e:
        print(f"Erro ao inicializar banco de dados: {e}")
        print("A aplicação pode não funcionar corretamente sem o banco de dados.")
        # Em produção, você pode querer fazer sys.exit(1) aqui
        # Para desenvolvimento, vamos continuar e deixar o erro aparecer quando necessário

# Resto do código permanece igual...
# [Aqui continuaria com todas as rotas e funções do arquivo original]

# Inicializar o banco de dados na primeira execução
if __name__ == '__main__':
    init_database()
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)), debug=False)
