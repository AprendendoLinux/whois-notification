# 🌐 Whois Notification

[![Docker Image Version](https://img.shields.io/docker/v/aprendendolinux/whois-notification?sort=semver)](https://hub.docker.com/r/aprendendolinux/whois-notification)
[![Docker Pulls](https://img.shields.io/docker/pulls/aprendendolinux/whois-notification)](https://hub.docker.com/r/aprendendolinux/whois-notification)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Bem-vindo ao repositório oficial do **Whois Notification**! 
Um sistema robusto, conteinerizado e totalmente automatizado para monitoramento pró-ativo de datas de expiração de domínios. 

Repositório Oficial: [https://github.com/AprendendoLinux/whois-notification](https://github.com/AprendendoLinux/whois-notification)

---

## 📖 Índice

1. [Introdução e Motivação](#-introdução-e-motivação)
2. [Arquitetura do Sistema](#-arquitetura-do-sistema)
3. [Funcionalidades Principais (Features)](#-funcionalidades-principais-features)
4. [Pré-requisitos de Instalação](#-pré-requisitos-de-instalação)
5. [Guia de Implantação (Quick Start)](#-guia-de-implantação-quick-start)
6. [Referência do docker-compose.yml](#-referência-do-docker-composeyml)
7. [Mapeamento de Volumes e Arquivos Base](#-mapeamento-de-volumes-e-arquivos-base)
8. [Configuração Avançada: domains.json](#-configuração-avançada-domainsjson)
9. [Comportamento do Agendador (Scheduler)](#-comportamento-do-agendador-scheduler)
10. [Notificações e Estados de Alerta](#-notificações-e-estados-de-alerta)
11. [Troubleshooting e Resolução de Problemas](#-troubleshooting-e-resolução-de-problemas)
12. [Contribuição](#-contribuição)

---

## 🎯 Introdução e Motivação

Perder a data de renovação de um domínio estratégico é um dos incidentes mais críticos para qualquer infraestrutura de TI, podendo resultar em indisponibilidade imediata de sites corporativos, falhas na entrega de e-mails, perda de confiança de clientes e, em casos extremos, o sequestro do domínio por terceiros.

O **Whois Notification** foi projetado para mitigar esse risco de forma definitiva. Operando 100% em background via Docker, ele realiza consultas diárias aos servidores de registro global (WHOIS) e orquestra o envio de alertas multicanal (Telegram e E-mail HTML customizado) garantindo que a equipe de infraestrutura ou a diretoria sejam avisadas com antecedência parametrizável.

---

## 🏗 Arquitetura do Sistema

O sistema é construído utilizando uma abordagem *cloud-native* baseada em contêineres:

```text
+-------------------+       +-----------------------+       +-------------------+
|                   |       |                       | ----> | Servidor WHOIS    |
|   domains.json    | ----> |  Container Docker     |       | (Registro.br, etc)|
|   (Regras)        |       |  (Python 3.11 Slim)   | <---- | Datas / Status    |
|                   |       |                       |       +-------------------+
+-------------------+       |  [ Scheduler 24/7 ]   |
                            |  [ Lógica de Alertas] | ----> +-------------------+
+-------------------+       |  [ Parser de WHOIS  ] |       | API do Telegram   |
|                   | ----> |                       |       | (Mensagem Push)   |
|   logo.* (Imagem) |       +-----------------------+       +-------------------+
+-------------------+                   |
                                        |                   +-------------------+
                                        +-----------------> | Servidor SMTP     |
                                                            | (E-mail HTML)     |
                                                            +-------------------+
```

---

## ✨ Funcionalidades Principais (Features)

*   **Monitoramento Universal:** Suporte a virtualmente qualquer TLD (Terminação de domínio), incluindo `.com`, `.com.br`, `.net`, `.dev`, `.online`, etc. Graças à integração nativa com o binário `whois` do Linux em conjunto com a biblioteca `python-whois`.
*   **Granularidade de Alertas:** Cada domínio possui sua própria régua de corte (`days_threshold`). O domínio da empresa pode alertar com 45 dias de antecedência, enquanto um domínio secundário alerta com apenas 15.
*   **Alertas Multicanal por Domínio:** Direcione alertas de domínios específicos para equipes específicas. O domínio de TI vai para o grupo do Telegram de Infra; o domínio do RH vai para o e-mail da diretoria.
*   **Auto-provisionamento Segregado:** Se o sistema inicializar sem um arquivo de configuração, ele constrói automaticamente um modelo instrutivo (boilerplate) na máquina host para evitar crash-loops.
*   **Identificação Dinâmica de Assets (Logo):** Mapeie a pasta inteira de dados. O sistema localizará automaticamente a sua imagem de marca (PNG, JPG, SVG, JPEG, etc.) via varredura MIME para anexar inline nos relatórios via e-mail.
*   **Escalonamento de Severidade:** Se o domínio efetivamente expirar, as notificações mudam drasticamente o tom, layout (coletor vermelho escuro) e assunto, alertando para um *status de expiração*.
*   **Agendamento Resiliente:** Processo diário fixo sem vazamento de memória (memory leaks), executado por um agendador Python (`schedule`) validado em aplicações corporativas.

---

## 🛠 Pré-requisitos de Instalação

*   Servidor rodando **Linux** (Debian, Ubuntu, CentOS, etc).
*   **Docker Engine** instalado (versão 20.10+ recomendada).
*   **Docker Compose** (versão V2 / plugin).
*   Acesso a um servidor **SMTP** autêntico (ex: Mailcow, Postfix, Gmail App Passwords, Sendgrid).
*   Um **Bot do Telegram** configurado através do @BotFather.

---

## 🚀 Guia de Implantação (Quick Start)

### Passo 1: Preparando a estrutura de diretórios do Host
O container precisa de um volume no host para ler as configurações e a imagem de logo de forma persistente.

```bash
sudo mkdir -p /srv/whois-notification
cd /srv/whois-notification
```

Coloque dentro dessa pasta o seu arquivo de logotipo (ex: `logo.png`, `logo.jpg`).

### Passo 2: Criar o arquivo de orquestração
Crie o arquivo `docker-compose.yml` (veja a seção seguinte para os parâmetros).

### Passo 3: Inicialização
Suba a stack em *detached mode*:

```bash
docker-compose up -d
```

Neste exato momento, se não houver um `domains.json`, o container criará um modelo padrão automaticamente na sua pasta `/srv/whois-notification`.

### Passo 4: Verifique os logs
Acompanhe o que o sistema está fazendo:
```bash
docker-compose logs -f
```

---

## ⚙️ Referência do docker-compose.yml

Utilizamos a imagem oficial armazenada no DockerHub `aprendendolinux/whois-notification:latest`. Abaixo, um manifesto completo com **dados genéricos** de exemplo. Preencha com as variáveis do seu ambiente de produção.

```yaml
version: '3.8'

services:
  whois_notification:
    image: ghcr.io/aprendendolinux/whois-notification:latest
    container_name: whois_notification
    # Mapeamento do diretório completo para flexibilidade de arquivos (JSON e Imagens)
    volumes:
      - /srv/whois-notification:/app/data
    environment:
      # Configurações do Telegram
      # Obtenha o token conversando com o @BotFather no Telegram
      - TELEGRAM_BOT_TOKEN=123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789
      
      # Configurações de E-mail (Servidor SMTP)
      - SMTP_SERVER=smtp.exemplo.com.br
      - SMTP_PORT=587
      - SMTP_USER=alertas@exemplo.com.br
      - SMTP_PASSWORD=sua_senha_super_secreta
      
      # Metadados de Envio
      - SMTP_FROM=alertas@exemplo.com.br
      - SMTP_FROM_NAME=Whois Notification System
      
      # Definir timezone adequado para o agendamento correto (ex: 09:00 AM local)
      - TZ=America/Sao_Paulo
    restart: unless-stopped
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

---

## 📂 Mapeamento de Volumes e Arquivos Base

A diretiva `- /srv/whois-notification:/app/data` diz ao Docker que tudo dentro dessa pasta física no seu servidor espelhará dentro do container.

O sistema espera encontrar (ou criará) dois tipos de arquivos ali:
1. `domains.json` - O motor de regras.
2. `logo.*` - Qualquer arquivo que inicie com o nome "logo", para compor os e-mails HTML.

---

## 📝 Configuração Avançada: domains.json

Este é o cérebro das regras de negócios. É um array de objetos JSON, onde cada objeto dita as regras de um domínio distinto.

```json
[
  {
    "domain": "suaempresa.com.br",
    "emails": [
        "infra@suaempresa.com.br", 
        "diretoria@suaempresa.com.br"
    ],
    "telegrams": [
        "111111111", 
        "-10022222222"
    ],
    "days_threshold": 45
  },
  {
    "domain": "projeto-secundario.dev",
    "emails": ["devops@suaempresa.com.br"],
    "telegrams": [],
    "days_threshold": 15
  }
]
```

**Parâmetros de cada nó:**
*   `domain` (string): O FQDN (Fully Qualified Domain Name) do domínio. **Sem http/https ou www.**
*   `emails` (array de strings): Lista de caixas postais que receberão o HTML. Deixe vazio `[]` para não enviar e-mail.
*   `telegrams` (array de strings): Lista de Chat IDs do Telegram (podem ser IDs de usuários privados ou de grupos começando com `-100`). Deixe vazio `[]` para não enviar via telegram.
*   `days_threshold` (inteiro): A partir de quantos dias restantes a notificação deve começar a ser disparada.

---

## ⏱ Comportamento do Agendador (Scheduler)

O ciclo de vida do script segue o seguinte *pipeline*:

1. **Bootstrapping (Arranque):** Ao executar `docker-compose up -d`, o Python inicia o motor, realiza o *bind* das variáveis de ambiente e faz um `check_domains()` imediatamente. Isso é útil para validar se as configurações estão funcionais assim que o serviço sobe.
2. **Scheduling (Agendamento):** O daemon principal entra em loop (verificando a cada 60 segundos o relógio do sistema).
3. **Trigger Diário:** Todos os dias, pontualmente às **09:00 AM** (considerando o timezone configurado no container), as regras de checagem disparam e novos relatórios WHOIS são gerados e validados contra os limites configurados.

---

## 🚨 Notificações e Estados de Alerta

O sistema trabalha com dois perfis psicológicos de alerta (UX/UI de notificação):

### 🟡 Alerta Preventivo (Faltam dias positivos)
Quando a conta `Data de Expiração - Data de Hoje` é menor que o `threshold` estipulado, mas é **maior ou igual a 0**.
*   **E-mail:** Design com cabecalho Vermelho (`#d32f2f`), banner Laranja de atenção e mensagem sugerindo a renovação a fim de evitar suspensão.
*   **Telegram:** Começa com ícone ⚠️ e avisa que o domínio "expira em X dias".

### 🔴 Alerta Crítico (Domínio Expirado - Dias negativos)
Quando a data passa do limite estipulado (Dias = -1, -2...). O sistema **não para de alertar** para garantir a recuperação durante o período de "Redemption Grace Period" das registradoras.
*   **E-mail:** Design emergencial, cabeçalho Sangue (`#b71c1c`), boxes vermelhos e mensagem afirmando que "O Domínio EXPIROU e precisa ser renovado IMEDIATAMENTE".
*   **Telegram:** Ícones de sirene 🚨 e alerta ostensivo informando os dias em atraso.

---

## 🛠 Troubleshooting e Resolução de Problemas

**1. Erro ao consultar a data do domínio.**
*   *Sintoma:* Logs acusam `Erro ao consultar o domínio...` e enviam resultado "Não foi possível obter os dados".
*   *Solução:* Alguns TLDs exóticos (ex: `.ai`, `.io`) podem ter servidores WHOIS com bloqueio de rate-limit. Verifique se o seu servidor não está em blacklist nos servidores de quem registra.

**2. O e-mail não chega.**
*   *Sintoma:* Nenhum e-mail na caixa de entrada.
*   *Solução:* Verifique os Logs do container. Se constar erro no SMTP, confira suas credenciais, portas (587 TLS ou 465 SSL) e se sua provedora (como Gmail ou Office365) não exige uma "App Password" em vez da senha normal. Verifique sua caixa de SPAM.

**3. O ID do chat no Telegram dá "Chat not found".**
*   *Sintoma:* A API do Telegram devolve erro 400.
*   *Solução:* O seu Bot precisa primeiro conversar com a pessoa ou ser adicionado ao grupo ANTES de enviar a mensagem ativa. Envie um `/start` para o bot através da conta/grupo que deve receber as mensagens.

**4. A Imagem (Logo) vai quebrada no e-mail.**
*   *Solução:* Garanta que há apenas UMA imagem começando com `logo.` na pasta mapeada. O sistema varre e pega o primeiro `logo.*` que encontrar, processando via MIME dinâmico.

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
