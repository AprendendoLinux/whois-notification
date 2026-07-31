import os
import time
import json
import whois
import schedule
import requests
import smtplib
import glob
import mimetypes
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.utils import formataddr

# Configurações Globais (Vindas do docker-compose)
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM = os.getenv("SMTP_FROM")
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "Whois Notification")

def get_first_date(date_obj):
    if isinstance(date_obj, list):
        return date_obj[0]
    return date_obj

def format_date(date_obj):
    d = get_first_date(date_obj)
    if isinstance(d, datetime):
        return d.strftime('%d/%m/%Y')
    elif isinstance(d, str):
        return d
    return "Indisponível"

def format_status(status_obj):
    if not status_obj:
        return "Indisponível"
    
    if isinstance(status_obj, list):
        st = status_obj[0]
    else:
        st = str(status_obj)
        
    return st.split()[0].upper() if st.strip() else "Indisponível"

def get_domain_info(domain_name):
    try:
        w = whois.whois(domain_name)
        
        exp_date_raw = get_first_date(w.expiration_date)
        creation_date = format_date(w.creation_date)
        updated_date = format_date(w.updated_date)
        expiration_date_str = format_date(w.expiration_date)
        status = format_status(w.status)
        
        return {
            "success": True,
            "exp_date_obj": exp_date_raw if isinstance(exp_date_raw, datetime) else None,
            "creation_date": creation_date,
            "updated_date": updated_date,
            "expiration_date": expiration_date_str,
            "status": status
        }
    except Exception as e:
        print(f"Erro ao consultar o domínio {domain_name}: {e}")
        return {"success": False}

def send_telegram(domain, days_left, info, chats):
    if not TELEGRAM_TOKEN or not chats:
        return
    
    if days_left < 0:
        dias_expirado = abs(days_left)
        msg = (f"🚨 *Whois Notification - DOMÍNIO EXPIRADO* 🚨\n\n"
               f"O domínio *{domain}* EXPIROU há *{dias_expirado} dias*!\n\n"
               f"🏷 *Status Atual:* {info['status']}\n"
               f"🗓 *Criação:* {info['creation_date']}\n"
               f"🔄 *Última Modificação:* {info['updated_date']}\n"
               f"🛑 *Data de Expiração:* {info['expiration_date']}\n\n"
               f"⚠️ *RENOVE IMEDIATAMENTE* para evitar a perda definitiva do domínio.")
    else:
        msg = (f"⚠️ *Whois Notification - ALERTA* ⚠️\n\n"
               f"O domínio *{domain}* expira em *{days_left} dias*!\n\n"
               f"🏷 *Status Atual:* {info['status']}\n"
               f"🗓 *Criação:* {info['creation_date']}\n"
               f"🔄 *Última Modificação:* {info['updated_date']}\n"
               f"🛑 *Data de Expiração:* {info['expiration_date']}\n\n"
               f"Renove o quanto antes para evitar interrupções.")
    
    for chat_id in chats:
        if chat_id:
            url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
            payload = {"chat_id": chat_id, "text": msg, "parse_mode": "Markdown"}
            requests.post(url, json=payload)

def send_email(domain, days_left, info, recipients):
    if not SMTP_USER or not recipients:
        return

    msg = MIMEMultipart('related')
    
    is_expired = days_left < 0
    abs_days = abs(days_left)
    
    if is_expired:
        subject = f"🚨 URGENTE: O Domínio {domain} EXPIROU há {abs_days} dias!"
        header_text = "DOMÍNIO EXPIRADO"
        header_bg = "#b71c1c"
        intro_text = f"O sistema <strong>Whois Notification</strong> identificou que o domínio <strong style='color: #b71c1c; font-size: 18px;'>{domain}</strong> <strong>já expirou</strong> no dia {info['expiration_date']} e deve ser renovado IMEDIATAMENTE."
        days_box_bg = "#ffebee"
        days_box_border = "#f44336"
        days_box_title_color = "#c62828"
        days_box_title = f"Expirado há {abs_days} dias"
        days_box_sub = "Risco altíssimo de perda definitiva e indisponibilidade de serviços"
    else:
        subject = f"🚨 AÇÃO NECESSÁRIA: Domínio {domain} expira em {days_left} dias!"
        header_text = "Alerta de Expiração"
        header_bg = "#d32f2f"
        intro_text = f"O sistema <strong>Whois Notification</strong> identificou que o domínio <strong style='color: #d32f2f; font-size: 18px;'>{domain}</strong> requer sua atenção imediata."
        days_box_bg = "#fff4e5"
        days_box_border = "#ff9800"
        days_box_title_color = "#e65100"
        days_box_title = f"{days_left} dias restantes"
        days_box_sub = "Para o cancelamento do domínio"

    msg['Subject'] = subject
    msg['From'] = formataddr((SMTP_FROM_NAME, SMTP_FROM))
    msg['To'] = ", ".join(recipients)

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
    </head>
    <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f0f2f5; margin: 0; padding: 40px 20px;">
        <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">
            <tr>
                <td align="center" style="background-color: {header_bg}; padding: 30px 20px;">
                    <img src="cid:logo" alt="Logo" style="max-height: 80px; margin-bottom: 15px; display: block; border-radius: 4px;">
                    <h1 style="color: #ffffff; margin: 0; font-size: 24px; text-transform: uppercase; letter-spacing: 1px;">{header_text}</h1>
                </td>
            </tr>
            <tr>
                <td style="padding: 40px 30px;">
                    <p style="font-size: 18px; color: #333333; margin-top: 0;">Olá,</p>
                    <p style="font-size: 16px; color: #555555; line-height: 1.5;">{intro_text}</p>
                    
                    <div style="background-color: {days_box_bg}; border-left: 5px solid {days_box_border}; padding: 15px 20px; margin: 25px 0; border-radius: 0 4px 4px 0;">
                        <h2 style="margin: 0 0 5px 0; color: {days_box_title_color}; font-size: 28px;">{days_box_title}</h2>
                        <span style="color: #555555; font-size: 14px;">{days_box_sub}</span>
                    </div>

                    <table border="0" cellpadding="12" cellspacing="0" width="100%" style="background-color: #f9f9f9; border: 1px solid #eeeeee; border-radius: 6px;">
                        <tr>
                            <td width="40%" style="color: #666666; font-weight: bold; border-bottom: 1px solid #eeeeee;">🏷 Status do Domínio:</td>
                            <td width="60%" style="color: #333333; border-bottom: 1px solid #eeeeee; font-weight: bold;">{info['status']}</td>
                        </tr>
                        <tr>
                            <td style="color: #666666; font-weight: bold; border-bottom: 1px solid #eeeeee;">📅 Data de Registro:</td>
                            <td style="color: #333333; border-bottom: 1px solid #eeeeee;">{info['creation_date']}</td>
                        </tr>
                        <tr>
                            <td style="color: #666666; font-weight: bold; border-bottom: 1px solid #eeeeee;">🔄 Última Modificação:</td>
                            <td style="color: #333333; border-bottom: 1px solid #eeeeee;">{info['updated_date']}</td>
                        </tr>
                        <tr>
                            <td style="color: #d32f2f; font-weight: bold;">🛑 Data de Expiração:</td>
                            <td style="color: #d32f2f; font-weight: bold;">{info['expiration_date']}</td>
                        </tr>
                    </table>
                </td>
            </tr>
            <tr>
                <td align="center" style="background-color: #f8f9fa; padding: 20px; border-top: 1px solid #eeeeee;">
                    <p style="margin: 0; font-size: 12px; color: #aaaaaa;">Mensagem automática gerada pelo sistema <strong>Whois Notification</strong>.</p>
                </td>
            </tr>
        </table>
    </body>
    </html>
    """
    
    msg_alternative = MIMEMultipart('alternative')
    msg.attach(msg_alternative)
    msg_alternative.attach(MIMEText(html, 'html'))

    logo_files = glob.glob('/app/data/logo.*')
    if logo_files:
        logo_path = logo_files[0]
        logo_filename = os.path.basename(logo_path)
        
        try:
            ctype, encoding = mimetypes.guess_type(logo_path)
            if ctype is None or not ctype.startswith('image/'):
                ctype = 'application/octet-stream'
                
            maintype, subtype = ctype.split('/', 1)
            
            with open(logo_path, 'rb') as img_file:
                img = MIMEBase(maintype, subtype)
                img.set_payload(img_file.read())
                encoders.encode_base64(img)
                img.add_header('Content-ID', '<logo>')
                img.add_header('Content-Disposition', 'inline', filename=logo_filename)
                msg.attach(img)
        except Exception as e:
            print(f"Aviso: Erro ao anexar a imagem {logo_path}: {e}")
    else:
        print("Aviso: Nenhuma imagem de logo encontrada em /app/data/logo.*")

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_FROM, recipients, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Erro ao enviar e-mail para {domain}: {e}")

def create_example_config(config_path):
    """Cria um arquivo domains.json de exemplo se ele não existir."""
    example_data = [
        {
            "_comentario": "Substitua exemplo.com.br pelo seu dominio. O campo '_comentario' eh apenas instrucional e pode ser apagado.",
            "domain": "exemplo.com.br",
            "emails": ["contato@suaempresa.com.br", "ti@suaempresa.com.br"],
            "telegrams": ["SEU_CHAT_ID_1", "SEU_CHAT_ID_2"],
            "days_threshold": 30
        },
        {
            "_comentario": "Para dominios que precisam de mais tempo de aviso, aumente o days_threshold.",
            "domain": "outroexemplo.net",
            "emails": ["diretoria@suaempresa.com.br"],
            "telegrams": [],
            "days_threshold": 45
        }
    ]
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(example_data, f, indent=4, ensure_ascii=False)
        print(f"[*] ARQUIVO DE EXEMPLO CRIADO: O arquivo '{config_path}' foi gerado automaticamente.")
        print("[*] ACAO NECESSARIA: Edite este arquivo com os seus domínios reais.")
    except Exception as e:
        print(f"Erro ao tentar criar o arquivo de exemplo: {e}")

def check_domains():
    print(f"\n[{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}] Iniciando Whois Notification...")
    
    config_path = "/app/data/domains.json"
    
    # 1. Verifica se o arquivo existe; se não, cria.
    if not os.path.exists(config_path):
        create_example_config(config_path)
        print("[*] Aguardando a próxima execução (ou edite o arquivo e reinicie o container)...\n")
        return # Para a execução atual, dando tempo para o usuário editar

    # 2. Se existir, carrega os dados
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            domains_config = json.load(f)
    except Exception as e:
        print(f"Erro ao ler arquivo domains.json (verifique a formatação do JSON): {e}")
        return

    # 3. Processa cada domínio
    for config in domains_config:
        domain = config.get("domain")
        
        # Pula domínios de exemplo para evitar notificações indevidas
        if domain in ["exemplo.com.br", "outroexemplo.net"]:
            print(f"-> Ignorando domínio de exemplo configurado: {domain}")
            continue

        emails = config.get("emails", [])
        telegrams = config.get("telegrams", [])
        threshold = config.get("days_threshold", 30)

        info = get_domain_info(domain)
        
        if info["success"] and info["exp_date_obj"]:
            delta = info["exp_date_obj"] - datetime.now()
            days_left = delta.days
            
            status_text = f"Faltam {days_left} dias" if days_left >= 0 else f"Expirado há {abs(days_left)} dias"
            print(f"{domain}: {status_text} (Status: {info['status']} | Data limite: {info['expiration_date']})")
            
            if days_left <= threshold:
                print(f" -> [ALERTA] Enviando notificações para {domain}")
                send_telegram(domain, days_left, info, telegrams)
                send_email(domain, days_left, info, emails)
        else:
            print(f"Não foi possível obter os dados de expiração para: {domain}")

if __name__ == "__main__":
    check_domains()
    
    schedule.every().day.at("09:00").do(check_domains)
    
    print("Serviço Whois Notification rodando e agendado. Aguardando...")
    while True:
        schedule.run_pending()
        time.sleep(60)
