from app import app
from unittest.mock import patch, MagicMock


def test_pagina_inicial():
    app.config["TESTING"] = True
    cliente = app.test_client()

    resposta = cliente.get("/")

    assert resposta.status_code == 200


def test_pagina_sql_vulneravel():
    app.config["TESTING"] = True
    cliente = app.test_client()

    resposta = cliente.get("/sql-injection")

    assert resposta.status_code == 200
    assert b"Consulta construida por concatenacao" in resposta.data or (
        "Consulta construída por concatenação".encode("utf-8")
        in resposta.data
    )



def test_pagina_sql_segura():
    app.config["TESTING"] = True
    cliente = app.test_client()

    resposta = cliente.get("/sql-injection-seguro")

    assert resposta.status_code == 200
    assert "Consulta parametrizada".encode("utf-8") in resposta.data
    
def test_login_valido_modo_seguro():
    app.config["TESTING"] = True
    cliente = app.test_client()

    cursor_falso = MagicMock()
    cursor_falso.fetchone.return_value = {
        "id": 1,
        "usuario": "alice_teste"
    }

    conexao_falsa = MagicMock()
    conexao_falsa.cursor.return_value = cursor_falso

    with patch("app.conectar_banco", return_value=conexao_falsa):
        resposta = cliente.post(
            "/sql-injection-seguro",
            data={
                "usuario": "alice_teste",
                "senha": "senha_ficticia_123"
            }
        )

    assert resposta.status_code == 200
    assert b"Login aceito para: alice_teste" in resposta.data
    
    

def test_login_invalido_modo_seguro():
    app.config["TESTING"] = True
    cliente = app.test_client()

    cursor_falso = MagicMock()
    cursor_falso.fetchone.return_value = None

    conexao_falsa = MagicMock()
    conexao_falsa.cursor.return_value = cursor_falso

    with patch("app.conectar_banco", return_value=conexao_falsa):
        resposta = cliente.post(
            "/sql-injection-seguro",
            data={
                "usuario": "usuario_inexistente",
                "senha": "senha_errada"
            }
        )

    assert resposta.status_code == 200
    assert "Usuário ou senha inválidos.".encode("utf-8") in resposta.data
    
    

def test_consulta_segura_usa_parametros_separados():
    app.config["TESTING"] = True
    cliente = app.test_client()

    cursor_falso = MagicMock()
    cursor_falso.fetchone.return_value = None

    conexao_falsa = MagicMock()
    conexao_falsa.cursor.return_value = cursor_falso

    with patch("app.conectar_banco", return_value=conexao_falsa):
        cliente.post(
            "/sql-injection-seguro",
            data={
                "usuario": "alice_teste",
                "senha": "senha_ficticia_123"
            }
        )

    argumentos = cursor_falso.execute.call_args

    assert argumentos is not None

    consulta, parametros = argumentos.args

    assert "%s" in consulta
    assert parametros == ("alice_teste", "senha_ficticia_123")
    
    

def test_consulta_vulneravel_monta_sql_por_concatenacao():
    app.config["TESTING"] = True
    cliente = app.test_client()

    cursor_falso = MagicMock()
    cursor_falso.fetchone.return_value = None

    conexao_falsa = MagicMock()
    conexao_falsa.cursor.return_value = cursor_falso

    with patch("app.conectar_banco", return_value=conexao_falsa):
        cliente.post(
            "/sql-injection",
            data={
                "usuario": "alice_teste",
                "senha": "senha_ficticia_123"
            }
        )

    consulta = cursor_falso.execute.call_args.args[0]

    assert "'alice_teste'" in consulta
    assert "'senha_ficticia_123'" in consulta
    

def test_login_hash_valido():
    app.config["TESTING"] = True
    cliente = app.test_client()

    from werkzeug.security import generate_password_hash

    hash_falso = generate_password_hash("SenhaFicticia123!")

    cursor_falso = MagicMock()
    cursor_falso.fetchone.return_value = {
        "id": 1,
        "usuario": "carol_segura",
        "senha_hash": hash_falso
    }

    conexao_falsa = MagicMock()
    conexao_falsa.cursor.return_value = cursor_falso

    with patch("app.conectar_banco", return_value=conexao_falsa):
        resposta = cliente.post(
            "/login-hash",
            data={
                "usuario": "carol_segura",
                "senha": "SenhaFicticia123!"
            }
        )

    assert resposta.status_code == 200
    assert b"Login aceito para: carol_segura" in resposta.data
    

def test_login_hash_senha_incorreta():
    app.config["TESTING"] = True
    cliente = app.test_client()

    from werkzeug.security import generate_password_hash

    hash_falso = generate_password_hash("SenhaFicticia123!")

    cursor_falso = MagicMock()
    cursor_falso.fetchone.return_value = {
        "id": 1,
        "usuario": "carol_segura",
        "senha_hash": hash_falso
    }

    conexao_falsa = MagicMock()
    conexao_falsa.cursor.return_value = cursor_falso

    with patch("app.conectar_banco", return_value=conexao_falsa):
        resposta = cliente.post(
            "/login-hash",
            data={
                "usuario": "carol_segura",
                "senha": "SenhaErrada123!"
            }
        )

    assert resposta.status_code == 200
    assert "Usuário ou senha inválidos.".encode("utf-8") in resposta.data
    
    

def test_login_hash_usuario_inexistente():
    app.config["TESTING"] = True
    cliente = app.test_client()

    cursor_falso = MagicMock()
    cursor_falso.fetchone.return_value = None

    conexao_falsa = MagicMock()
    conexao_falsa.cursor.return_value = cursor_falso

    with patch("app.conectar_banco", return_value=conexao_falsa):
        resposta = cliente.post(
            "/login-hash",
            data={
                "usuario": "usuario_que_nao_existe",
                "senha": "SenhaFicticia123!"
            }
        )

    assert resposta.status_code == 200
    assert "Usuário ou senha inválidos.".encode("utf-8") in resposta.data
    
    

def test_consulta_segura_trata_caracteres_especiais():
    app.config["TESTING"] = True
    cliente = app.test_client()

    cursor_falso = MagicMock()
    cursor_falso.fetchone.return_value = None

    conexao_falsa = MagicMock()
    conexao_falsa.cursor.return_value = cursor_falso

    usuario_teste = "alice'teste"
    senha_teste = "senha'com'aspas"

    with patch("app.conectar_banco", return_value=conexao_falsa):
        cliente.post(
            "/sql-injection-seguro",
            data={
                "usuario": usuario_teste,
                "senha": senha_teste
            }
        )

    consulta, parametros = cursor_falso.execute.call_args.args

    assert "%s" in consulta
    assert parametros == (usuario_teste, senha_teste)
    

def test_perfil_redireciona_quando_nao_autenticado():
    app.config["TESTING"] = True
    cliente = app.test_client()

    resposta = cliente.get("/perfil")

    assert resposta.status_code == 302
    assert "/login" in resposta.headers["Location"]


def test_logout_limpa_sessao():
    app.config["TESTING"] = True
    cliente = app.test_client()

    with cliente.session_transaction() as sessao:
        sessao["usuario_id"] = 1
        sessao["usuario_nome"] = "Alice Teste"
        sessao["usuario_perfil"] = "usuario"

    resposta = cliente.post("/logout")

    assert resposta.status_code == 302
    assert "/login" in resposta.headers["Location"]

    with cliente.session_transaction() as sessao:
        assert "usuario_id" not in sessao
        assert "usuario_nome" not in sessao
        assert "usuario_perfil" not in sessao
        

def test_login_valido_cria_sessao():
    from werkzeug.security import generate_password_hash

    app.config["TESTING"] = True
    cliente = app.test_client()

    usuario_falso = {
        "id": 7,
        "nome": "Alice Teste",
        "email": "alice@example.test",
        "senha_hash": generate_password_hash("SenhaFicticia123!"),
        "perfil": "usuario"
    }

    cursor_falso = MagicMock()
    cursor_falso.fetchone.return_value = usuario_falso

    conexao_falsa = MagicMock()
    conexao_falsa.cursor.return_value = cursor_falso

    with patch("app.conectar_banco", return_value=conexao_falsa):
        resposta = cliente.post(
            "/login",
            data={
                "email": "alice@example.test",
                "senha": "SenhaFicticia123!"
            }
        )

    assert resposta.status_code == 302
    assert "/perfil" in resposta.headers["Location"]

    with cliente.session_transaction() as sessao:
        assert sessao["usuario_id"] == 7
        assert sessao["usuario_nome"] == "Alice Teste"
        assert sessao["usuario_perfil"] == "usuario"
        

def test_perfil_mostra_usuario_da_sessao():
    app.config["TESTING"] = True
    cliente = app.test_client()

    with cliente.session_transaction() as sessao:
        sessao["usuario_id"] = 2
        sessao["usuario_nome"] = "Bob Teste"
        sessao["usuario_perfil"] = "usuario"

    cursor_falso = MagicMock()
    cursor_falso.fetchone.return_value = {
        "id": 2,
        "nome": "Bob Teste",
        "email": "bob@example.test",
        "perfil": "usuario"
    }

    conexao_falsa = MagicMock()
    conexao_falsa.cursor.return_value = cursor_falso

    with patch("app.conectar_banco", return_value=conexao_falsa):
        resposta = cliente.get("/perfil")

    assert resposta.status_code == 200
    assert b"Bob Teste" in resposta.data
    assert b"alice@example.test" not in resposta.data

    consulta, parametros = cursor_falso.execute.call_args.args
    assert "WHERE id = %s" in consulta
    assert parametros == (2,)
    

def test_perfil_vulneravel_permite_acessar_outro_usuario():
    app.config["TESTING"] = True
    cliente = app.test_client()

    with cliente.session_transaction() as sessao:
        sessao["usuario_id"] = 1
        sessao["usuario_perfil"] = "usuario"

    cursor_falso = MagicMock()
    cursor_falso.fetchone.return_value = {
        "id": 2,
        "nome": "Bob Teste",
        "email": "bob@example.test",
        "perfil": "usuario"
    }

    conexao_falsa = MagicMock()
    conexao_falsa.cursor.return_value = cursor_falso

    with patch("app.conectar_banco", return_value=conexao_falsa):
        resposta = cliente.get("/perfil/2")

    assert resposta.status_code == 200
    assert b"Bob Teste" in resposta.data


def test_perfil_seguro_bloqueia_outro_usuario():
    app.config["TESTING"] = True
    cliente = app.test_client()

    with cliente.session_transaction() as sessao:
        sessao["usuario_id"] = 1
        sessao["usuario_perfil"] = "usuario"

    cursor_falso = MagicMock()
    cursor_falso.fetchone.return_value = {
        "id": 2,
        "nome": "Bob Teste",
        "email": "bob@example.test",
        "perfil": "usuario"
    }

    conexao_falsa = MagicMock()
    conexao_falsa.cursor.return_value = cursor_falso

    with patch("app.conectar_banco", return_value=conexao_falsa):
        resposta = cliente.get("/perfil-seguro/2")

    assert resposta.status_code == 403
    assert b"Acesso negado." in resposta.data


def test_perfil_seguro_permite_proprio_perfil():
    app.config["TESTING"] = True
    cliente = app.test_client()

    with cliente.session_transaction() as sessao:
        sessao["usuario_id"] = 1
        sessao["usuario_perfil"] = "usuario"

    cursor_falso = MagicMock()
    cursor_falso.fetchone.return_value = {
        "id": 1,
        "nome": "Alice Teste",
        "email": "alice@example.test",
        "perfil": "usuario"
    }

    conexao_falsa = MagicMock()
    conexao_falsa.cursor.return_value = cursor_falso

    with patch("app.conectar_banco", return_value=conexao_falsa):
        resposta = cliente.get("/perfil-seguro/1")

    assert resposta.status_code == 200
    assert b"Alice Teste" in resposta.data
    

def test_perfil_seguro_permite_admin_acessar_outro_usuario():
    app.config["TESTING"] = True
    cliente = app.test_client()

    with cliente.session_transaction() as sessao:
        sessao["usuario_id"] = 2
        sessao["usuario_perfil"] = "usuario"

    cursor_falso = MagicMock()
    cursor_falso.fetchone.side_effect = [
        {
            "id": 1,
            "nome": "Alice Teste",
            "email": "alice@example.test",
            "perfil": "usuario"
        },
        {
            "perfil": "admin"
        }
    ]

    conexao_falsa = MagicMock()
    conexao_falsa.cursor.return_value = cursor_falso

    with patch("app.conectar_banco", return_value=conexao_falsa):
        resposta = cliente.get("/perfil-seguro/1")

    assert resposta.status_code == 200
    assert b"Alice Teste" in resposta.data
    

def test_perfil_seguro_respeita_perfil_atual_do_banco():
    app.config["TESTING"] = True
    cliente = app.test_client()

    # A sessão ainda diz "admin", mas o banco diz "usuario".
    with cliente.session_transaction() as sessao:
        sessao["usuario_id"] = 2
        sessao["usuario_perfil"] = "admin"

    cursor_falso = MagicMock()
    cursor_falso.fetchone.side_effect = [
        {
            "id": 1,
            "nome": "Alice Teste",
            "email": "alice@example.test",
            "perfil": "usuario"
        },
        {
            "perfil": "usuario"
        }
    ]

    conexao_falsa = MagicMock()
    conexao_falsa.cursor.return_value = cursor_falso

    with patch("app.conectar_banco", return_value=conexao_falsa):
        resposta = cliente.get("/perfil-seguro/1")

    assert resposta.status_code == 403
    assert b"Acesso negado." in resposta.data
    

def test_perfil_seguro_redireciona_quem_nao_esta_logado():
    app.config["TESTING"] = True
    cliente = app.test_client()

    resposta = cliente.get("/perfil-seguro/1")

    assert resposta.status_code == 302
    assert "/login" in resposta.headers["Location"]
    

def test_configuracoes_de_seguranca_da_sessao():
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["SESSION_COOKIE_SECURE"] is False
    

def test_nao_acessa_perfil_apos_logout():
    app.config["TESTING"] = True
    cliente = app.test_client()

    with cliente.session_transaction() as sessao:
        sessao["usuario_id"] = 1
        sessao["usuario_nome"] = "Alice Teste"
        sessao["usuario_perfil"] = "usuario"

    resposta_logout = cliente.post("/logout")
    resposta_perfil = cliente.get("/perfil")

    assert resposta_logout.status_code == 302
    assert resposta_perfil.status_code == 302
    assert "/login" in resposta_perfil.headers["Location"]