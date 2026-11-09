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
2. [Novidades da versão 2](#-novidades-da-versão-2)
3. [Arquitetura do Sistema](#-arquitetura-do-sistema)
4. [Funcionalidades](#-funcionalidades)
5. [Pré-requisitos](#-pré-requisitos)
6. [Guia de Implantação (Quick Start)](#-guia-de-implantação-quick-start)
7. [Atualizando da versão 1 (domains.json)](#-atualizando-da-versão-1-domainsjson)
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

## 🆕 Novidades da versão 2

* **Interface web** com painel visual: indicadores, radar de expirações para os próximos 12 meses e cartões por domínio.
* **Panorama completo do domínio**: WHOIS, registros DNS, segurança de e-mail (SPF, DMARC, DKIM), certificado SSL/TLS, disponibilidade HTTP, histórico e resposta WHOIS bruta.
* **Banco SQLite** no lugar do `domains.json`, com **migração automática** na primeira execução.
* **Alertas de certificado SSL** vencendo ou expirado.
* **Detecção de mudanças** em nameservers, registrador, status, MX e DNSSEC, com alerta de possível sequestro de domínio.
* **Política de alertas inteligente**: avisos em marcos (60, 45, 30, 15 e 7 dias) e diários na reta final, em vez de repetir a mesma mensagem todos os dias.
* **Configuração pela interface**: SMTP, Telegram, horário e política. As variáveis de ambiente continuam funcionando e têm prioridade.
* **Correções**: datas com fuso horário que impediam a verificação, suporte real à porta 465 (SSL), timeouts e registro de erros no Telegram.

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
                         +------------------+-------------------+
                                            |                    ----> API do Telegram / Servidor SMTP
                                 /app/data (volume)
                                 ├── whois.db  (SQLite)
                                 ├── logo.*    (logotipo dos e-mails)
                                 └── .secret_key
```

| Componente | Tecnologia |
|---|---|
| Backend e API | FastAPI + Uvicorn |
| Banco de dados | SQLite (SQLAlchemy 2 + migrações Alembic automáticas) |
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
* **Contatos reutilizáveis:** um e-mail ou chat do Telegram pode receber alertas de vários domínios. Cada contato tem um botão "Testar".
* **Escalonamento de Severidade:** os alertas mudam de tom e de cor quando o domínio está perto de expirar ou já expirou.
* **Logotipo nos e-mails:** coloque um arquivo `logo.*` (PNG, JPG, SVG...) no volume e ele aparece no cabeçalho dos e-mails.
* **Registro de eventos:** todos os envios, com sucesso ou falha, ficam registrados e aparecem na interface.

---

## 🛠 Pré-requisitos

* Servidor **Linux** com **Docker Engine** (20.10+) e **Docker Compose** V2.
* Opcional: acesso a um servidor **SMTP** (Mailcow, Postfix, Gmail com senha de app, SendGrid...).
* Opcional: um **bot do Telegram** criado pelo @BotFather.

---

## 🚀 Guia de Implantação (Quick Start)

### Passo 1: Preparar o diretório de dados

```bash
sudo mkdir -p /srv/whois-notification
cd /srv/whois-notification
```

Coloque nessa pasta o seu logotipo (ex.: `logo.png`), se quiser usá-lo nos e-mails.

### Passo 2: Criar o `docker-compose.yml`

Veja a [referência abaixo](#-referência-do-docker-composeyml).

### Passo 3: Subir o serviço

```bash
docker compose up -d
```

### Passo 4: Acessar o painel

Abra `http://SEU_SERVIDOR:8000`. Na primeira vez, o sistema pede para criar a conta de administrador. Se você definir `ADMIN_USER` e `ADMIN_PASSWORD`, ela é criada automaticamente.

Depois disso:
1. Em **Configurações**, preencha o SMTP e/ou o token do Telegram e use **Enviar teste**.
2. Em **Novo domínio**, cadastre seus domínios e os destinatários dos alertas.

### Passo 5: Acompanhar os logs

```bash
docker compose logs -f
```

---

## 🔄 Atualizando da versão 1 (domains.json)

Não é preciso fazer nada manualmente. Ao iniciar a versão 2 com o mesmo volume:

1. Se existir `/app/data/domains.json` e o banco estiver vazio, todos os domínios, e-mails, chats e limites são importados para o SQLite.
2. O arquivo é renomeado para `domains.json.migrated`, como backup. Ele não é apagado.
3. Os domínios de exemplo (`exemplo.com.br`, `outroexemplo.net`) e entradas inválidas são ignorados.
4. Uma varredura começa logo em seguida.

As variáveis de SMTP e Telegram da versão 1 continuam valendo. Só é preciso **publicar a porta 8000** no compose para acessar a interface.

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
      - /srv/whois-notification:/app/data
    environment:
      - TZ=America/Sao_Paulo
      # - ADMIN_USER=admin
      # - ADMIN_PASSWORD=troque_esta_senha
      # - COOKIE_SECURE=1
      # - TELEGRAM_BOT_TOKEN=123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789
      # - SMTP_SERVER=smtp.exemplo.com.br
      # - SMTP_PORT=587
      # - SMTP_SECURITY=starttls
      # - SMTP_USER=alertas@exemplo.com.br
      # - SMTP_PASSWORD=sua_senha_super_secreta
      # - SMTP_FROM=alertas@exemplo.com.br
      # - SMTP_FROM_NAME=Whois Notification System
    restart: unless-stopped
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

> **Importante:** o agendador roda dentro do processo da aplicação. Mantenha **um único container** (e um único worker) por banco de dados.

---

## 🔧 Variáveis de Ambiente

Todas são opcionais. As que configuram SMTP, Telegram e horário também podem ser editadas pela interface. Quando definidas no ambiente, **têm prioridade** e aparecem bloqueadas (🔒) na tela de Configurações.

| Variável | Padrão | Descrição |
|---|---|---|
| `TZ` | `America/Sao_Paulo` | Fuso do agendamento e da interface |
| `PORT` | `8000` | Porta HTTP dentro do container |
| `ADMIN_USER` / `ADMIN_PASSWORD` | — | Cria o administrador na primeira execução |
| `SECRET_KEY` | gerada em `/app/data/.secret_key` | Chave de assinatura das sessões |
| `COOKIE_SECURE` | `0` | Use `1` atrás de HTTPS |
| `CHECK_TIME` | `09:00` | Horário da varredura diária |
| `TELEGRAM_BOT_TOKEN` | — | Token do bot do Telegram |
| `SMTP_SERVER` | — | Servidor SMTP |
| `SMTP_PORT` | `587` | Porta SMTP |
| `SMTP_SECURITY` | `starttls` | `starttls`, `ssl` (porta 465) ou `none` |
| `SMTP_USER` / `SMTP_PASSWORD` | — | Credenciais SMTP |
| `SMTP_FROM` / `SMTP_FROM_NAME` | — / `Whois Notification` | Remetente |

---

## 🚨 Política de Alertas

A cada varredura, para a expiração do domínio e para a do certificado SSL:

1. **Fora da janela** (dias restantes acima do limite do domínio): nenhum alerta.
2. **Ao entrar na janela:** o primeiro alerta é enviado imediatamente.
3. **Marcos** (padrão `60, 45, 30, 15, 7`): um novo alerta a cada marco cruzado. Se a varredura do dia exato falhar, o alerta sai na próxima.
4. **Reta final** (padrão: 7 dias ou menos) e **depois de expirado:** um alerta por dia, sem parar, para garantir a recuperação durante o *Redemption Grace Period*.
5. **Nunca** mais de um alerta do mesmo tipo por dia. Quando o domínio é renovado, o ciclo recomeça.

Os marcos e o limite diário são ajustáveis em **Configurações**. Canais sem configuração (por exemplo, SMTP vazio) são ignorados, e o painel mostra um aviso.

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

* A interface exige login. As senhas são armazenadas com hash **scrypt**.
* Todos os formulários têm proteção **CSRF**, e o cookie de sessão é `HttpOnly` e `SameSite=Lax`.
* Senhas de SMTP e tokens nunca são exibidos na interface. Eles ficam no banco `whois.db`, então **proteja o volume** (`chmod 700 /srv/whois-notification`) ou use variáveis de ambiente.
* Para acesso pela internet, coloque um proxy reverso com HTTPS na frente (Nginx, Traefik, Caddy) e use `COOKIE_SECURE=1`.

---

## 💻 Desenvolvimento Local

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
DATA_DIR=./data .venv/bin/uvicorn app.main:app --reload --port 8000
```

* Documentação da API: `http://localhost:8000/api/docs` (exige login).
* Nova migração depois de alterar `app/models.py`:
  ```bash
  DATA_DIR=./data .venv/bin/python -m app.dbmigrate revision "descrição da mudança"
  ```

Estrutura:

```text
app/
├── main.py              # FastAPI, ciclo de vida, middlewares
├── models.py            # Tabelas SQLite
├── scheduler.py         # Agendamento diário e varreduras sob demanda
├── migrate_json.py      # Importação do domains.json (v1)
├── services/
│   ├── whois_service.py # Consulta WHOIS normalizada
│   ├── dns_service.py   # DNS, SPF, DMARC, DKIM, DNSSEC
│   ├── ssl_service.py   # Certificado TLS
│   ├── http_service.py  # Disponibilidade HTTP
│   ├── checker.py       # Orquestração, mudanças e política de alertas
│   ├── notifier.py      # E-mail e Telegram
│   └── settings.py      # Configurações (banco + ambiente)
├── routes/              # Páginas e API JSON
├── templates/           # Interface e template do e-mail
└── migrations/          # Alembic
```

---

## 🛠 Troubleshooting

**1. "Não foi possível obter os dados" / WHOIS falhou.**
Alguns TLDs (ex.: `.ai`, `.io`) limitam consultas. Veja o erro na aba *Histórico* do domínio. Os outros coletores (DNS, SSL, HTTP) continuam funcionando, e o último valor conhecido é mantido.

**2. O domínio aparece sem data de expiração.**
Alguns registros não publicam a data, como domínios diretamente sob `.br` (ex.: `registro.br`). O restante do panorama continua disponível.

**3. O e-mail não chega.**
Use **Configurações → Enviar teste**. O erro exato aparece na tela e em **Eventos**. Confira porta e segurança (587 + STARTTLS ou 465 + SSL) e se o provedor exige senha de app. Verifique a caixa de SPAM.

**4. Telegram responde "chat not found".**
O destinatário precisa enviar `/start` ao bot, ou o bot precisa estar no grupo, antes do primeiro envio.

**5. O logo aparece quebrado no e-mail.**
Mantenha apenas **uma** imagem começando com `logo.` na pasta mapeada. Sem nenhuma, o logotipo padrão do projeto é usado.

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
