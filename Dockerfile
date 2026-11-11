FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/AprendendoLinux/whois-notification" \
      org.opencontainers.image.description="Monitoramento de domínios com painel web: WHOIS, DNS, SSL, HTTP e alertas" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

# Cliente whois do sistema (fallback do python-whois para alguns TLDs)
RUN apt-get update \
 && apt-get install -y --no-install-recommends whois \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

VOLUME ["/app/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8000\")}/healthz', timeout=4)"

# Um único worker: o agendador roda dentro do processo da aplicação
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*' --workers 1"]
