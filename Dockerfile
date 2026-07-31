FROM python:3.11-slim

# Instala o cliente whois do sistema (melhora compatibilidade com vários TLDs)
RUN apt-get update && apt-get install -y whois && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instala as dependências diretamente
RUN pip install --no-cache-dir python-whois==0.9.4 requests==2.31.0 schedule==1.2.1

# Copia o código principal
COPY monitor.py .

# Executa o script sem buffering
CMD ["python", "-u", "monitor.py"]
