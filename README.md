# 🌐 Whois Notification

[![Docker Image Version](https://img.shields.io/docker/v/aprendendolinux/whois-notification?sort=semver)](https://hub.docker.com/r/aprendendolinux/whois-notification)
[![Docker Pulls](https://img.shields.io/docker/pulls/aprendendolinux/whois-notification)](https://hub.docker.com/r/aprendendolinux/whois-notification)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Bem-vindo ao repositório oficial do **Whois Notification**!
Um sistema conteinerizado para monitoramento pró-ativo de domínios, com **painel web**, **panorama completo de cada domínio** (WHOIS, DNS, e-mail, SSL e HTTP), **detecção de mudanças suspeitas** e alertas por **Telegram** e **e-mail**.

Repositório Oficial: [https://github.com/AprendendoLinux/whois-notification](https://github.com/AprendendoLinux/whois-notification)

---

## 📖 Índice

1. [Introdução e Motivação](#-introdução-e-motivação)
2. [Novidades da versão 3](#-novidades-da-versão-3)
3. [Arquitetura do Sistema](#-arquitetura-do-sistema)
4. [Funcionalidades](#-funcionalidades)
5. [Pré-requisitos](#-pré-requisitos)
6. [Guia de Implantação (Quick Start)](#-guia-de-implantação-quick-start)
7. [Multiusuário e administração](#-multiusuário-e-administração)
8. [Referência do docker-compose.yml](#-referência-do-docker-composeyml)
9. [Variáveis de Ambiente](#-variáveis-de-ambiente)
10. [Política de Alertas](#-política-de-alertas)
11. [Detecção de Mudanças](#-detecção-de-mudanças)
12. [Segurança](#-segurança)
13. [Desenvolvimento Local](#-desenvolvimento-local)
14. [Troubleshooting](#-troubleshooting)
15. [Contribuição](#-contribuição)

---

## 🎯 Introdução e Motivação

Perder a data de renovação de um domínio estratégico é um dos incidentes mais críticos para qualquer infraestrutura de TI, podendo resultar em indisponibilidade imediata de sites corporativos, falhas na entrega de e-mails, perda de confiança de clientes e, em casos extremos, o sequestro do domínio por terceiros.

O **Whois Notification** foi projetado para mitigar esse risco de forma definitiva. Ele consulta diariamente os servidores de registro (WHOIS), o DNS, o certificado TLS e o site de cada domínio, e orquestra o envio de alertas multicanal (Telegram e e-mail HTML) com antecedência parametrizável.

---

## 🆕 Novidades da versão 3

* **Banco MySQL** (`mysql:latest`) no lugar do SQLite. Na primeira execução, com o banco vazio, todas as tabelas são criadas automaticamente.
* **Multiusuário:** cada usuário tem seus próprios domínios, contatos, remetentes SMTP, bots do Telegram, agendamento e histórico. Um usuário nunca vê os dados do outro.
* **Área do administrador:** criar e excluir usuários, tornar ou revogar administrador, desativar/reativar, gerar senha temporária e configurar o sistema.
* **Tudo pela interface:** a única configuração por ambiente é a conexão com o banco. SMTP, Telegram, fuso horário e agendamento são feitos dentro do sistema.
* **Primeiro acesso seguro:** o usuário `admin` nasce com senha aleatória exibida nos logs do contêiner e a troca é obrigatória no primeiro login.
* **Recuperação de senha por e-mail** ("esqueci minha senha"). O e-mail é obrigatório no cadastro.
* **E-mails com a identidade do sistema:** visual escuro/neon e o logotipo do próprio Whois Notification.

---

## 🏗 Arquitetura do Sistema

```text
                         +--------------------------------------+
  Navegador  <---------> |  Container Docker (Python 3.12)      |
  (painel web)           |                                      |
                         |  FastAPI ── interface + API JSON     | ----> WHOIS (Registro.br, Verisign, ...)
                         |  APScheduler ── varredura diária     | ----> DNS (A, AAAA, NS, MX, TXT, CAA, DS)
                         |  Coletores ── WHOIS/DNS/SSL/HTTP     | ----> Porta 443 (certificado TLS)
                         |  Notificador ── e-mail / Telegram    | ----> HTTP(S) do site
                         +---------+-----------+----------+
                                   |                      |            ----> API do Telegram / Servidor SMTP
                         MySQL (container `db`)     /app/data (volume)
                         usuários, domínios,        ├── .secret_key (sessões)
                         histórico, remetentes      └── .enc_key    (criptografia dos segredos)
```

| Componente | Tecnologia |
|---|---|
| Backend e API | FastAPI + Uvicorn |
| Banco de dados | MySQL (SQLAlchemy 2 + PyMySQL; tabelas criadas automaticamente) |
| Agendador | APScheduler (no mesmo processo) |
| Interface | Jinja2, HTMX, Alpine.js e ECharts, servidos localmente (funciona sem internet) |

---

## ✨ Funcionalidades

* **Monitoramento Universal:** suporte a praticamente qualquer TLD (`.com`, `.com.br`, `.net`, `.dev`, `.online`, etc.).
* **Panorama por domínio:**
  * **WHOIS:** registrador, titular, datas, status EPP, nameservers e DNSSEC.
  * **DNS:** registros A, AAAA, NS, MX, TXT, CAA e SOA.
  * **E-mail:** análise de SPF, DMARC e DKIM, com nota de 0 a 100.
  * **SSL/TLS:** emissor, validade, cadeia confiável, nomes cobertos, protocolo e chave.
  * **HTTP:** status, tempo de resposta, redirecionamentos e cabeçalhos de segurança.
  * **Histórico:** gráfico de tempo de resposta, linha do tempo de mudanças e lista de varreduras.
* **Granularidade de Alertas:** cada domínio tem sua janela de alerta de expiração e de SSL.
* **Remetentes por usuário:** vários servidores SMTP e bots do Telegram, com um padrão e a opção de escolher outro em cada domínio.
* **Contatos reutilizáveis:** um e-mail ou chat do Telegram pode receber alertas de vários domínios. Cada contato tem um botão "Testar".
* **Escalonamento de Severidade:** os alertas mudam de tom e de cor quando o domínio está perto de expirar ou já expirou.
* **Registro de eventos:** todos os envios, com sucesso ou falha, ficam registrados e aparecem na interface.

---

## 🛠 Pré-requisitos

* Servidor **Linux** com **Docker Engine** (20.10+) e **Docker Compose** V2.
* Opcional: acesso a um servidor **SMTP** (Mailcow, Postfix, Gmail com senha de app, SendGrid...).
* Opcional: um **bot do Telegram** criado pelo @BotFather.

---

## 🚀 Guia de Implantação (Quick Start)

### Passo 1: Preparar os diretórios

```bash
sudo mkdir -p /srv/whois/app /srv/whois/mysql
```

### Passo 2: Criar o `docker-compose.yml`

Veja a [referência abaixo](#-referência-do-docker-composeyml). Troque as senhas do banco.

### Passo 3: Subir o serviço

```bash
docker compose up -d
```

### Passo 4: Primeiro acesso

Pegue a senha gerada para o `admin` nos logs:

```bash
docker compose logs whois_notification | grep -A4 "PRIMEIRO ACESSO"
```

Abra `http://SEU_SERVIDOR:8000`, entre como `admin` e, na tela seguinte, informe seu **e-mail** e defina uma **nova senha**. O sistema não deixa seguir antes disso.

Depois:
1. Em **Sistema** (menu do administrador), configure o SMTP usado na recuperação de senha, o fuso horário e a URL pública.
2. Em **Usuários**, crie as contas das demais pessoas.
3. Cada usuário cadastra seus **Remetentes** (SMTP e bots do Telegram), seus **Contatos** e seus **domínios**.

### Passo 5: Acompanhar os logs

```bash
docker compose logs -f
```

---

## 👥 Multiusuário e administração

| Ação | Quem faz |
|---|---|
| Cadastrar domínios, contatos, remetentes SMTP/Telegram, agendamento | Cada usuário, só para si |
| Criar/excluir usuários, tornar/revogar administrador, desativar/reativar, gerar senha temporária | Administrador (menu **Usuários**) |
| Fuso horário, URL pública e SMTP do sistema | Administrador (menu **Sistema**) |

* Usuários novos recebem uma **senha temporária** (definida pelo administrador ou gerada) e são obrigados a trocá-la no primeiro login.
* O sistema sempre mantém pelo menos **um administrador ativo**, e ninguém pode excluir, desativar ou rebaixar a si mesmo.
* Excluir um usuário apaga também todos os seus dados.
* **Esqueci minha senha:** o link é enviado ao e-mail da conta e vale por 1 hora, uso único. Usa o SMTP do sistema; se ele não estiver configurado, usa o remetente SMTP do próprio usuário.
* **Perdeu a senha do admin e não há e-mail configurado?** Gere uma nova senha temporária:
  ```bash
  docker exec whois_notification python -m app.cli reset-admin
  ```

---

## ⚙️ Referência do docker-compose.yml

```yaml
services:
  whois_notification:
    image: ghcr.io/aprendendolinux/whois-notification:latest
    container_name: whois_notification
    ports:
      - "8000:8000"
    volumes:
      # Chaves geradas no primeiro boot (sessão e criptografia dos segredos).
      # Faça backup junto com o banco: sem elas, as senhas SMTP/tokens salvos não podem ser lidas.
      - /srv/whois/app:/app/data
    environment:
      - DB_HOST=db
      - DB_PORT=3306
      - DB_NAME=whois
      - DB_USER=whois
      - DB_PASSWORD=troque_esta_senha
    restart: unless-stopped

  db:
    image: mysql:latest
    container_name: whois_db
    environment:
      - MYSQL_DATABASE=whois
      - MYSQL_USER=whois
      - MYSQL_PASSWORD=troque_esta_senha
      - MYSQL_ROOT_PASSWORD=troque_a_senha_root
    volumes:
      - /srv/whois/mysql:/var/lib/mysql
    restart: unless-stopped
```

> **Importante:** o agendador roda dentro do processo da aplicação. Mantenha **um único container** (e um único worker) por banco de dados.

---

## 🔧 Variáveis de Ambiente

Somente a conexão com o banco é configurada por ambiente. **Todo o resto é feito dentro do sistema.**

| Variável | Padrão | Descrição |
|---|---|---|
| `DB_HOST` | `db` | Host do MySQL |
| `DB_PORT` | `3306` | Porta do MySQL |
| `DB_NAME` | `whois` | Nome do banco |
| `DB_USER` | `whois` | Usuário do banco |
| `DB_PASSWORD` | — | Senha do banco |

Fuso horário, URL pública e SMTP do sistema: **Sistema** (administrador). Horário da varredura e política de alertas: **Configurações** (cada usuário).

---

## 🚨 Política de Alertas

A cada varredura, para a expiração do domínio e para a do certificado SSL:

1. **Fora da janela** (dias restantes acima do limite do domínio): nenhum alerta.
2. **Ao entrar na janela:** o primeiro alerta é enviado imediatamente.
3. **Marcos** (padrão `60, 45, 30, 15, 7`): um novo alerta a cada marco cruzado. Se a varredura do dia exato falhar, o alerta sai na próxima.
4. **Reta final** (padrão: 7 dias ou menos) e **depois de expirado:** um alerta por dia, sem parar, para garantir a recuperação durante o *Redemption Grace Period*.
5. **Nunca** mais de um alerta do mesmo tipo por dia. Quando o domínio é renovado, o ciclo recomeça.

Os marcos e o limite diário são ajustáveis por usuário em **Configurações**. Canais sem remetente cadastrado são ignorados, e o painel mostra um aviso.

### Perfis de alerta

* 🟡 **Preventivo:** o domínio ou certificado expira em X dias.
* 🔴 **Crítico:** faltam 7 dias ou menos, ou já expirou ("renove IMEDIATAMENTE").
* 🔁 **Mudança:** alteração de nameserver, registrador, status perigoso (`clientHold`, `serverHold`, `redemptionPeriod`, `pendingDelete`), MX ou DNSSEC desativado.

---

## 🕵️ Detecção de Mudanças

Cada varredura é comparada com a anterior. As mudanças aparecem na linha do tempo do domínio e no painel. As de severidade **crítica** ou **atenção** geram alerta, e isso pode ser desligado em Configurações.

Alguns servidores WHOIS respondem com dados diferentes conforme o servidor consultado (registro x registrador). Para evitar **falsos alertas de sequestro**, toda mudança de nameserver ou registrador é **confirmada com uma segunda consulta** antes de ser aceita.

---

## 🔒 Segurança

* A interface exige login. As senhas são armazenadas com hash **scrypt**, e há limite de tentativas de login e de recuperação.
* Todos os formulários têm proteção **CSRF**, e o cookie de sessão é `HttpOnly`, `SameSite=Lax` e `Secure` automaticamente quando acessado por HTTPS.
* Cada consulta é filtrada pelo usuário logado: um usuário não acessa domínios, contatos ou remetentes de outro, nem pela API.
* Senhas SMTP e tokens do Telegram são **criptografados** (Fernet) no banco e nunca exibidos na interface. A chave fica em `/app/data/.enc_key`.
* Redefinição de senha: token aleatório de uso único, guardado só como hash, válido por 1 hora.
* Para acesso pela internet, coloque um proxy reverso com HTTPS na frente (Nginx, Traefik, Caddy) e informe a URL pública em **Sistema**.

---

## 💻 Desenvolvimento Local

```bash
docker run -d --name whois-mysql -p 3306:3306 -e MYSQL_DATABASE=whois -e MYSQL_USER=whois \
  -e MYSQL_PASSWORD=dev -e MYSQL_ROOT_PASSWORD=dev mysql:latest
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
DB_HOST=127.0.0.1 DB_PASSWORD=dev .venv/bin/uvicorn app.main:app --reload --port 8000
```

* A senha inicial do `admin` aparece no terminal.
* Documentação da API: `http://localhost:8000/api/docs` (exige login).
* Não há migrações: as tabelas são criadas automaticamente quando não existem.

Estrutura:

```text
app/
├── main.py              # FastAPI, ciclo de vida, middlewares
├── models.py            # Tabelas MySQL
├── db.py                # Engine e criação das tabelas
├── auth.py              # Senhas, sessão, recuperação, admin inicial
├── crypto.py            # Criptografia dos segredos
├── scheduler.py         # Varredura diária por usuário
├── cli.py               # reset-admin
├── services/
│   ├── whois_service.py # Consulta WHOIS normalizada
│   ├── dns_service.py   # DNS, SPF, DMARC, DKIM, DNSSEC
│   ├── ssl_service.py   # Certificado TLS
│   ├── http_service.py  # Disponibilidade HTTP
│   ├── checker.py       # Orquestração, mudanças e política de alertas
│   ├── notifier.py      # E-mail e Telegram
│   ├── senders.py       # Resolução dos remetentes por usuário/domínio
│   └── settings.py      # Configurações do usuário e do sistema
├── routes/              # Páginas, administração e API JSON
└── templates/           # Interface e template do e-mail
```

---

## 🛠 Troubleshooting

**1. "Não foi possível obter os dados" / WHOIS falhou.**
Alguns TLDs (ex.: `.ai`, `.io`) limitam consultas. Veja o erro na aba *Histórico* do domínio. Os outros coletores (DNS, SSL, HTTP) continuam funcionando, e o último valor conhecido é mantido.

**2. O domínio aparece sem data de expiração.**
Alguns registros não publicam a data, como domínios diretamente sob `.br` (ex.: `registro.br`). O restante do panorama continua disponível.

**3. O e-mail não chega.**
Use o botão **Testar** em **Remetentes** ou **Contatos**. O erro exato aparece na tela e em **Eventos**. Confira porta e segurança (587 + STARTTLS ou 465 + SSL) e se o provedor exige senha de app. Verifique a caixa de SPAM.

**4. Telegram responde "chat not found".**
O destinatário precisa enviar `/start` ao bot, ou o bot precisa estar no grupo, antes do primeiro envio.

**5. O link de "esqueci minha senha" não chega.**
Configure o SMTP em **Sistema** (e use **Enviar teste**) ou cadastre um remetente SMTP na conta do usuário. Sem nenhum dos dois, o envio falha e o erro aparece nos logs do contêiner.

**6. DNSSEC aparece como "não assinado", mas o domínio é assinado.**
A verificação consulta o registro `DS` em resolvers públicos (1.1.1.1, 8.8.8.8, 9.9.9.9). Se o servidor bloquear DNS externo, o resultado pode sair incorreto.

---

## 🤝 Contribuição

Contribuições, issues e feature requests são super bem-vindos!
Sinta-se à vontade para checar a página de [issues](https://github.com/AprendendoLinux/whois-notification/issues).

1. Faça o Fork do projeto.
2. Crie uma Branch para sua Feature (`git checkout -b feature/AmazingFeature`).
3. Faça o Commit de suas mudanças (`git commit -m 'Add some AmazingFeature'`).
4. Faça o Push para a Branch (`git push origin feature/AmazingFeature`).
5. Abra um Pull Request.

---

Desenvolvido com 💻 e ☕ por [AprendendoLinux](https://github.com/AprendendoLinux).
