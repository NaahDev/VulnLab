# VulnLab — Laboratório de Segurança Web

Laboratório educacional desenvolvido para estudar vulnerabilidades web, testar correções e compreender boas práticas de desenvolvimento seguro.

## 🎯 Objetivos

- Compreender o funcionamento de SQL Injection em um ambiente controlado.
- Comparar consultas SQL vulneráveis e consultas parametrizadas.
- Aprender a armazenar senhas usando hashes.
- Implementar autenticação, sessões e controle de acesso.
- Criar testes automatizados para validar o comportamento da aplicação.
- Desenvolver conhecimentos práticos em Python, Flask, MySQL e segurança de aplicações.

## 🛠️ Tecnologias

- Python
- Flask
- MySQL
- HTML, CSS e JavaScript
- pytest
- Werkzeug
- mysql-connector-python

## 🚀 Funcionalidades implementadas

- Página inicial do laboratório.
- Demonstração controlada de SQL Injection.
- Comparação entre consultas SQL vulneráveis e parametrizadas.
- Autenticação com senhas armazenadas em hash.
- Login com consulta SQL parametrizada.
- Gerenciamento de sessões com Flask.
- Cookies de sessão configurados com `HttpOnly` e `SameSite=Lax`.
- Páginas privadas protegidas contra acesso sem autenticação.
- Controle de acesso para usuários comuns e administradores.
- Demonstração de falha de autorização e sua versão corrigida.
- Logout com encerramento da sessão.
- Testes automatizados com pytest, mocks e cliente de testes do Flask.

## 🔐 Segurança

Este projeto foi criado exclusivamente para fins educacionais e deve ser executado em ambiente local controlado.

- Os dados utilizados no laboratório são fictícios.
- As rotas vulneráveis existem exclusivamente para demonstração.
- As versões seguras utilizam consultas SQL parametrizadas.
- As senhas da versão segura são armazenadas como hashes.
- A autorização é verificada no servidor.
- Os testes automatizados utilizam objetos simulados para validar a lógica da aplicação.
- A chave secreta da aplicação é carregada por variável de ambiente.

**Não publique as rotas vulneráveis na internet nem utilize credenciais ou dados reais.**

## 💻 Como executar localmente

1. Crie e ative um ambiente virtual Python.
2. Instale as dependências:

   ```bash
   pip install -r requirements.txt
   ```

3. Configure as variáveis de ambiente no arquivo `.env`.
4. Crie o banco `vulnlab` e execute os scripts SQL do projeto.
5. Execute a aplicação:

   ```bash
   python app.py
   ```

6. Acesse `http://127.0.0.1:5000`.

Não compartilhe o arquivo `.env` nem publique suas chaves secretas.

## 🧪 Testes automatizados

Para executar os testes:

```bash
python -m pytest -v
```

A suíte automatizada verifica comportamentos como:

- Funcionamento das páginas.
- Autenticação válida e inválida.
- Uso de parâmetros SQL.
- Criação e encerramento de sessões.
- Proteção de páginas privadas.
- Controle de acesso a perfis de usuários.
- Permissões de administradores.
- Configurações de segurança dos cookies de sessão.

**Resultado registrado:** 23 testes automatizados passaram na última execução confirmada.

## 🔎 Testes práticos de SQL Injection

### Objetivo

Comparar uma consulta SQL vulnerável com uma consulta protegida por parametrização, utilizando exclusivamente o ambiente local e dados fictícios.

### Teste 1 — Login legítimo

- **Rotas:** `/sql-injection` e `/sql-injection-seguro`
- **Resultado:** login aceito nas duas versões com credenciais válidas.
- **Conclusão:** o fluxo normal de autenticação funciona nas duas implementações.

### Teste 2 — Credenciais inválidas

- **Rotas:** `/sql-injection` e `/sql-injection-seguro`
- **Resultado:** ambas rejeitaram uma senha incorreta.
- **Conclusão:** o login normal rejeita credenciais inválidas, mas isso não é suficiente para comprovar a segurança contra SQL Injection.

### Teste 3 — Condição SQL verdadeira

- **Rota:** `/sql-injection`
- **Resultado observado:** a entrada manipulada foi aceita como login sem a senha correta.
- **Conclusão:** a concatenação direta de entradas permitiu alterar a lógica da consulta SQL.

### Teste 4 — Mesma tentativa na versão segura

- **Rota:** `/sql-injection-seguro`
- **Resultado observado:** a tentativa foi rejeitada com a mensagem `Usuário ou senha inválidos.`
- **Conclusão:** a consulta parametrizada impediu que a entrada fosse interpretada como parte da instrução SQL nesse cenário.

### Teste 5 — Condição SQL falsa

- **Rota:** `/sql-injection`
- **Resultado observado:** a tentativa foi rejeitada com a mensagem de credenciais inválidas.
- **Conclusão:** o resultado foi compatível com a condição falsa utilizada no teste.

### Teste 6 — Entrada com aspa simples

- **Rota vulnerável:** `/sql-injection`
- **Resultado observado:** a aplicação exibiu uma mensagem genérica de falha na consulta.
- **Rota segura:** `/sql-injection-seguro`
- **Resultado observado:** a aplicação rejeitou a entrada como credenciais inválidas, sem erro de sintaxe SQL visível.

### Medida de proteção

A versão segura utiliza parâmetros (`%s`) e envia os valores separadamente da instrução SQL. Dessa forma, os dados informados pelo usuário não são incorporados diretamente à sintaxe da consulta.

### Escopo dos testes

Os testes práticos foram executados localmente no VulnLab, com dados fictícios. Os resultados documentados correspondem aos comportamentos observados durante os experimentos.

A demonstração vulnerável deve permanecer isolada e não pode ser disponibilizada publicamente.

## 🔑 Controle de acesso e autorização

O VulnLab possui uma rota vulnerável e uma rota corrigida para demonstrar os riscos de acessar recursos de outros usuários por meio da alteração de identificadores na URL.

| Rota | Finalidade |
|---|---|
| `/login` | Autentica o usuário por e-mail e senha. |
| `/perfil` | Exibe o perfil do usuário autenticado. |
| `/perfil/<usuario_id>` | Demonstra uma falha de autorização no laboratório local. |
| `/perfil-seguro/<usuario_id>` | Verifica a autorização antes de exibir o perfil solicitado. |
| `/logout` | Encerra a sessão por uma requisição POST. |

### Regras de autorização

- Usuários não autenticados são redirecionados para o login.
- Usuários comuns podem acessar somente o próprio perfil na rota segura.
- Administradores podem consultar perfis de outros usuários.
- O perfil de acesso é consultado diretamente no banco de dados.
- Solicitações sem permissão recebem o código HTTP 403.

### Cenários verificados

- Acesso ao próprio perfil.
- Bloqueio de acesso a perfis de terceiros para usuários comuns.
- Acesso autorizado a outros perfis por administradores.
- Redirecionamento de usuários não autenticados.
- Encerramento da sessão após o logout.

## 📌 Próximos passos

- Implementar e testar uma demonstração controlada de XSS.
- Investigar SSTI em uma rota de laboratório específica.
- Melhorar a validação de entradas e o tratamento de erros.
- Ampliar a cobertura dos testes automatizados.
- Documentar novas vulnerabilidades e suas respectivas correções.
- Revisar as configurações de segurança antes de qualquer implantação.

---

**VulnLab — aprender segurança na prática, entender as vulnerabilidades e desenvolver soluções mais seguras.**