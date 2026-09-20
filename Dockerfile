FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PATH=/usr/local/go/bin:/go/bin:/usr/local/bin:$PATH GOPATH=/go
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git dnsutils nmap openssl whois sslscan whatweb nikto \
    build-essential libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libffi8 \
    libjpeg62-turbo libopenjp2-7 libglib2.0-0 libgdk-pixbuf-2.0-0 \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://go.dev/dl/go1.24.6.linux-amd64.tar.gz | tar -C /usr/local -xz
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.7 && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@v1.7.0 && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1 && \
    go install github.com/projectdiscovery/katana/cmd/katana@v1.1.3 && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.4.10 && \
    go install github.com/tomnomnom/assetfinder@v0.1.1 && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/tomnomnom/anew@latest && \
    go install github.com/ffuf/ffuf/v2@latest
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app app
COPY static static
COPY scripts scripts
COPY README.md README.md
RUN mkdir -p /app/reports /app/work && useradd -r -u 10001 -g root basha && chown -R 10001:0 /app && chmod -R g=u /app
USER 10001
EXPOSE 7860 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request, os; p = os.getenv('PORT', '7860'); urllib.request.urlopen(f'http://127.0.0.1:{p}/api/health',timeout=3)"
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-7860}"]
