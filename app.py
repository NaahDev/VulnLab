import os
import mysql.connector
from dotenv import load_dotenv
from flask import Flask, render_template, request, session, redirect, url_for
from werkzeug.security import check_password_hash

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False


def conectar_banco():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )


@app.route("/")
def inicio():
    return render_template("index.html")


@app.route("/sql-injection", methods=["GET", "POST"])
def sql_injection():
    mensagem = None
    diagnostico = "Consulta construída por concatenação (modo vulnerável)"

    if request.method == "POST":
        usuario = request.form.get("usuario", "")
        senha = request.form.get("senha", "")

        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True, buffered=True)

        try:
            # SOMENTE PARA ESTUDO LOCAL:
            # esta consulta é intencionalmente vulnerável.
            consulta = (
                "SELECT id, usuario FROM contas_teste "
                f"WHERE usuario = '{usuario}' "
                f"AND senha = '{senha}'"
            )

            cursor.execute(consulta)
            resultado = cursor.fetchone()

            if resultado:
                mensagem = f"Login aceito para: {resultado['usuario']}"
            else:
                mensagem = "Usuário ou senha inválidos."

        except mysql.connector.Error:
            mensagem = "A consulta falhou. Verifique os dados de teste."

        finally:
            cursor.close()
            conexao.close()

    return render_template(
        "sql_injection.html",
        mensagem=mensagem,
        modo="vulneravel",
        diagnostico=diagnostico
    )


@app.route("/sql-injection-seguro", methods=["GET", "POST"])
def sql_injection_seguro():
    mensagem = None
    diagnostico = "Consulta parametrizada (modo seguro)"

    if request.method == "POST":
        usuario = request.form.get("usuario", "")
        senha = request.form.get("senha", "")

        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

        try:
            cursor.execute(
                """
                SELECT id, usuario
                FROM contas_teste
                WHERE usuario = %s AND senha = %s
                """,
                (usuario, senha)
            )

            resultado = cursor.fetchone()

            if resultado:
                mensagem = f"Login aceito para: {resultado['usuario']}"
            else:
                mensagem = "Usuário ou senha inválidos."

        except mysql.connector.Error:
            mensagem = "Não foi possível processar o login."

        finally:
            cursor.close()
            conexao.close()

    return render_template(
        "sql_injection.html",
        mensagem=mensagem,
        modo="seguro",
        diagnostico=diagnostico
    )


@app.route("/login-hash", methods=["GET", "POST"])
def login_hash():
    mensagem = None
    diagnostico = "Consulta parametrizada + verificação de hash"

    if request.method == "POST":
        usuario = request.form.get("usuario", "")
        senha = request.form.get("senha", "")

        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

        try:
            cursor.execute(
                """
                SELECT id, usuario, senha_hash
                FROM contas_seguras
                WHERE usuario = %s
                """,
                (usuario,)
            )

            resultado = cursor.fetchone()

            if resultado and check_password_hash(
                resultado["senha_hash"], senha
            ):
                mensagem = f"Login aceito para: {resultado['usuario']}"
            else:
                mensagem = "Usuário ou senha inválidos."

        except mysql.connector.Error:
            mensagem = "Não foi possível processar o login."

        finally:
            cursor.close()
            conexao.close()

    return render_template(
        "sql_injection.html",
        mensagem=mensagem,
        modo="seguro",
        diagnostico=diagnostico
    )



@app.route("/login", methods=["GET", "POST"])
def login():
    mensagem = None

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        senha = request.form.get("senha", "")

        conexao = conectar_banco()
        cursor = conexao.cursor(dictionary=True)

        try:
            cursor.execute(
                """
                SELECT id, nome, email, senha_hash, perfil
                FROM usuarios
                WHERE email = %s
                """,
                (email,)
            )
            usuario = cursor.fetchone()

            if usuario and check_password_hash(
                usuario["senha_hash"], senha
            ):
                session.clear()
                session["usuario_id"] = usuario["id"]
                session["usuario_nome"] = usuario["nome"]
                session["usuario_perfil"] = usuario["perfil"]

                return redirect(url_for("perfil"))

            mensagem = "E-mail ou senha inválidos."

        except mysql.connector.Error:
            mensagem = "Não foi possível processar o login."

        finally:
            cursor.close()
            conexao.close()

    return render_template("login.html", mensagem=mensagem)


@app.route("/perfil")
def perfil():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    conexao = conectar_banco()
    cursor = conexao.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT id, nome, email, perfil
            FROM usuarios
            WHERE id = %s
            """,
            (session["usuario_id"],)
        )
        usuario = cursor.fetchone()

        if usuario is None:
            session.clear()
            return redirect(url_for("login"))

        return render_template("perfil.html", usuario=usuario)

    except mysql.connector.Error:
        return "Não foi possível carregar o perfil.", 500

    finally:
        cursor.close()
        conexao.close()
        

@app.route("/perfil/<int:usuario_id>")
def perfil_vulneravel(usuario_id):
    """Demonstração local de falha de autorização."""
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    conexao = conectar_banco()
    cursor = conexao.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT id, nome, email, perfil
            FROM usuarios
            WHERE id = %s
            """,
            (usuario_id,)
        )
        usuario = cursor.fetchone()

        if usuario is None:
            return "Usuário não encontrado.", 404

        # VULNERÁVEL: não verifica se o perfil pertence
        # ao usuário autenticado ou se ele é administrador.
        return render_template("perfil.html", usuario=usuario)

    except mysql.connector.Error:
        return "Não foi possível carregar o perfil.", 500

    finally:
        cursor.close()
        conexao.close()


@app.route("/perfil-seguro/<int:usuario_id>")
def perfil_seguro(usuario_id):
    """Versão com verificação de autorização."""
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    conexao = conectar_banco()
    cursor = conexao.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT id, nome, email, perfil
            FROM usuarios
            WHERE id = %s
            """,
            (usuario_id,)
        )
        usuario = cursor.fetchone()

        cursor.execute(
            """
            SELECT perfil
            FROM usuarios
            WHERE id = %s
            """,
            (session["usuario_id"],)
        )

        usuario_logado = cursor.fetchone()

        if usuario_logado is None:
            session.clear()
            return redirect(url_for("login"))

        if (
            usuario_id != session["usuario_id"]
            and usuario_logado["perfil"] != "admin"
        ):
            return "Acesso negado.", 403


        return render_template("perfil.html", usuario=usuario)

    except mysql.connector.Error:
        return "Não foi possível carregar o perfil.", 500

    finally:
        cursor.close()
        conexao.close()


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    # Disponível somente na máquina local.
    app.run(host="127.0.0.1", port=5000, debug=True)