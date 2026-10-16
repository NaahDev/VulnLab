import os
import mysql.connector
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

usuario = "carol_segura"
senha = "SenhaFicticia123!"

senha_hash = generate_password_hash(senha)

conexao = mysql.connector.connect(
    host=os.getenv("DB_HOST"),
    port=int(os.getenv("DB_PORT", "3306")),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME")
)

cursor = conexao.cursor()

try:
    cursor.execute(
        """
        INSERT INTO contas_seguras (usuario, senha_hash)
        VALUES (%s, %s)
        """,
        (usuario, senha_hash)
    )
    conexao.commit()
    print("Usuário de teste cadastrado com sucesso!")
except mysql.connector.IntegrityError:
    print("Esse usuário já existe.")
finally:
    cursor.close()
    conexao.close()