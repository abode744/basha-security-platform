#!/usr/bin/env bash
set -e

# ==============================================================================
# Script to install all security tools natively on Debian / Ubuntu
# ==============================================================================

echo "[+] Updating apt repositories..."
sudo apt-get update -y

echo "[+] Installing standard packages & libraries..."
sudo apt-get install -y --no-install-recommends \
    curl ca-certificates git build-essential \
    dnsutils nmap openssl whois sslscan whatweb nikto \
    python3-pip python3-venv

# Install Go if not present
if ! command -v go >/dev/null 2>&1; then
    echo "[+] Installing Go..."
    curl -fsSL https://go.dev/dl/go1.24.6.linux-amd64.tar.gz | sudo tar -C /usr/local -xz
    export PATH=/usr/local/go/bin:/go/bin:$HOME/go/bin:$PATH
fi

echo "[+] Installing ProjectDiscovery & TomNomNom reconnaissance tools via Go..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.7
go install github.com/projectdiscovery/httpx/cmd/httpx@v1.7.0
go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1
go install github.com/projectdiscovery/katana/cmd/katana@v1.1.3
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.4.10
go install github.com/tomnomnom/assetfinder@v0.1.1
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/anew@latest
go install github.com/ffuf/ffuf/v2@latest

# Copy go binaries to /usr/local/bin so all users can execute them
sudo cp $HOME/go/bin/* /usr/local/bin/ 2>/dev/null || true

# Install Python-based tools
echo "[+] Installing Python security tools (wafw00f)..."
pip3 install wafw00f --break-system-packages 2>/dev/null || pip3 install wafw00f || true

echo "[+] Verifying installed tools:"
bash "$(dirname "$0")/check_tools.sh"

echo "[✔] All 20/20 Tools installed and operational!"
