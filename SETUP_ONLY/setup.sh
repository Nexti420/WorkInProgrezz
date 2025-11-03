#!/bin/bash
################################################################################
# Pentesty CTF Machine - Dwufazowy Setup Script (POPRAWIONY)
# Faza 1: Instalacja pakietów (wymaga restartu)
# Faza 2: Konfiguracja usług (po restarcie)
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [ "$EUID" -ne 0 ]; then 
    log_error "Uruchom jako root: sudo bash $0"
    exit 1
fi

MARKER_FILE="/root/.pentesty_ctf_phase"

################################################################################
# FAZA 1: INSTALACJA PAKIETÓW
################################################################################

if [ ! -f "$MARKER_FILE" ]; then
    log_info "=== FAZA 1: Instalacja pakietów ==="
    
    log_info "Aktualizacja systemu..."
    apt update
    
    log_info "Instalacja pakietów..."
    DEBIAN_FRONTEND=noninteractive apt install -y \
        net-tools vim git curl wget \
        openssh-server vsftpd \
        apache2 php libapache2-mod-php \
        fail2ban docker.io gpg
    
    # Oznacz fazę 1 jako zakończoną
    echo "phase1_complete" > "$MARKER_FILE"
    
    if [ -f /var/run/reboot-required ]; then
        log_warning "╔════════════════════════════════════════════════════════╗"
        log_warning "║  WYMAGANY RESTART!                                     ║"
        log_warning "║                                                        ║"
        log_warning "║  Wykonaj:                                              ║"
        log_warning "║  1. sudo reboot                                        ║"
        log_warning "║  2. Po restarcie: sudo bash $0                         ║"
        log_warning "╚════════════════════════════════════════════════════════╝"
        exit 0
    else
        log_success "Pakiety zainstalowane - kontynuuję konfigurację..."
        echo "phase2_ready" > "$MARKER_FILE"
    fi
fi

################################################################################
# FAZA 2: KONFIGURACJA
################################################################################

if grep -q "phase1_complete\|phase2_ready" "$MARKER_FILE" 2>/dev/null; then
    log_info "=== FAZA 2: Konfiguracja usług ==="
    
    # 1. ZMIANA HASŁA ROOT
    log_info "Ustawianie hasła root..."
    echo "root:B6D5qTvFGKgNq\$" | chpasswd
    log_success "Hasło root zmienione"
    
    # 2. Użytkownicy
    log_info "Konfiguracja użytkowników..."
    
    # FTP User - BEZ dostępu do Dockera
    if ! id "ftpuser" &>/dev/null; then
        useradd -m -s /bin/bash ftpuser
        echo "ftpuser:FtpUser123" | chpasswd
    fi
    
    usermod -r -G docker ftpuser 2>/dev/null || true
    
    # Dev User - Z OGRANICZONYM dostępem do Dockera (przez wrapper scripts)
    if ! id "devuser" &>/dev/null; then
        useradd -m -s /bin/bash devuser
    fi
    echo "devuser:vzz3vMbbZHcpoeZX5VasAdCZ1" | chpasswd
    # usermod -aG docker devuser
    
    log_success "Użytkownicy skonfigurowani (ftpuser: BEZ docker, devuser: OGRANICZONY dostęp)"
    
    # 3. SSH
    log_info "Konfiguracja SSH..."
    
    # Sprawdź czy konfiguracja już istnieje
    if ! grep -q "# CTF Configuration" /etc/ssh/sshd_config; then
        cat >> /etc/ssh/sshd_config << 'EOF'

# CTF Configuration
PermitRootLogin prohibit-password
PubkeyAuthentication yes
Banner /etc/ssh/banner.txt

# FTP user - tylko klucze SSH, bez hasła
Match User ftpuser
    PasswordAuthentication no
    PubkeyAuthentication yes
EOF
    fi
    
    cat > /etc/ssh/banner.txt << 'EOF'
***************************************************************************
*                                                                         *
*  UWAGA: Nieautoryzowany dostęp do tego systemu jest zabroniony!         *
*                                                                         *
*  Wszystkie próby włamania są monitorowane i rejestrowane.               *
*  Naruszenie zabezpieczeń będzie ścigane zgodnie z prawem.               *
*                                                                         *
*  Login to this system by adding your public key to a                    *
*  file in your home directory called authorized_keys.                    *
*                                                                         *
***************************************************************************


EOF
    
    cat /etc/ssh/banner.txt > /etc/motd
    
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    
    if [ ! -f /root/.ssh/root_key ]; then
        ssh-keygen -t ed25519 -f /root/.ssh/root_key -N "HasloDoOdszyfrowania123" -q
        cp /root/.ssh/root_key.pub /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys
    fi
    
    systemctl restart sshd
    log_success "SSH skonfigurowany (ftpuser: tylko klucze, bez hasła)"
    
    # 4. Fail2ban
    log_info "Konfiguracja Fail2ban..."
    
    cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 60
findtime = 60
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    log_success "Fail2ban skonfigurowany"
    
        
    # 5. FTP Server (podatny wektor)
    log_info "Konfiguracja FTP..."
    
    # Przygotuj katalog .ssh dla ftpuser
    mkdir -p /home/ftpuser/.ssh
    chown -R ftpuser:ftpuser /home/ftpuser
    chmod 755 /home/ftpuser
    chmod 700 /home/ftpuser/.ssh
    
    # Dodaj pliki dla realizmu
    cat > /home/ftpuser/readme.txt << 'FTPEOF'
Welcome to the FTP server!

This is your home directory. You can upload files here.
FTPEOF
    
    cat > /home/ftpuser/notes.txt << 'FTPEOF'
Project notes:
- Remember to check the dev repository
- SSH keys can be useful for automation
- Check /home/ftpuser/.ssh for SSH configuration
FTPEOF
    
    touch /home/ftpuser/backup_20241030.tar.gz
    touch /home/ftpuser/config.json
    touch /home/ftpuser/deployment_script.sh
    
    cat > /home/ftpuser/todo.txt << 'FTPEOF'
TODO:
[ ] Update SSH keys
[ ] Review security settings
[ ] Check authorized_keys file
FTPEOF
    
    # Ukryty plik z hintem
    cat > /home/ftpuser/.hint << 'FTPEOF'
Hint: SSH accepts public keys in ~/.ssh/authorized_keys
FTPEOF
    
    chown ftpuser:ftpuser /home/ftpuser/*
    chown ftpuser:ftpuser /home/ftpuser/.*
    chmod 644 /home/ftpuser/*.txt
    chmod 644 /home/ftpuser/.hint
    
    # Konfiguracja vsftpd
    cat > /etc/vsftpd.conf << 'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
allow_writeable_chroot=YES
user_sub_token=$USER
local_root=/home/$USER
pasv_min_port=40000
pasv_max_port=40100
EOF
    
    systemctl restart vsftpd
    systemctl enable vsftpd
    log_success "FTP skonfigurowany (port 21, user: ftpuser)"

    # 6. HTTP
    log_info "Konfiguracja HTTP..."
        
    cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Development Portal</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container { text-align: center; }
        h1 { font-size: 3em; margin-bottom: 20px; }
        .link { color: #ffd700; text-decoration: none; font-size: 1.2em; }
        .footer { position: fixed; bottom: 10px; right: 10px; font-size: 0.8em; opacity: 0.3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚧 Work in Progress 🚧</h1>
        <p>Check current development here: <a href="https://github.com/Nexti420/WorkInProgrezz" class="link">Development Repository</a></p>
        <img src="https://i.redd.it/useo8hrsi6k91.png"  width="50%" />
    </div>
    <div class="footer">Powered by SHA-512</div>
</body>
</html>
EOF

    cat > /var/www/html/404.html << 'EOF'
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 Not Found</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container { text-align: center; }
        h1 { font-size: 3em; margin-bottom: 20px; }
        .link { color: #ffd700; text-decoration: none; font-size: 1.2em; }
        .footer { position: fixed; bottom: 10px; right: 10px; font-size: 0.8em; opacity: 0.3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚧 404 Not Found 🚧</h1>
        <p>The requested URL was not found on this server.</p>
        <img src="https://media.gettyimages.com/id/161710356/photo/police-officer-motioning-to-stop.jpg?s=612x612&w=gi&k=20&c=GF8JCsBVnmfnFsO2YleivOAzitjvz0wQgll9TWmzuA8="  width="70%" />
    </div>
    <div class="footer">Keep looking - MbbZH</div>
</body>
</html>
EOF
    
    mkdir -p /var/www/html/check
    cat > /var/www/html/check/index.html << 'EOF'
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <title>Hash Checker</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #1a1a1a; color: #00ff00; padding: 20px; }
        .hidden-button { position: fixed; top: 10px; left: 10px; width: 50px; height: 50px; opacity: 0.05; background: #727272; border: none; cursor: pointer; }
        table { border-collapse: collapse; margin: 20px auto; width: 80%; }
        th, td { border: 1px solid #00ff00; padding: 10px; text-align: left; }
        th { background: #003300; }
    </style>
</head>
<body>
    <button class="hidden-button" id="cpoeZ" onclick="refresh()"></button>
    <h1>🔐 Password Verification System</h1>
    <table>
        <tr><th>Zusammen</th><th>2098b3fbf03864f834ca831398afa8d4d274c1bd5ddec8e916d5855765040edd5c8dfb9d668d1dc5dbd877ea9d87b69cf0c552180a06549871437dd5be63376f</th></tr>
        <tr><td>Fragment 1/5</td><td>7f231b530bcf82d51d616129ec6365681600692bcbd9d3ea3ba6e01a524f5ed1687e984feeaf331cf9eb4e0116aae39827a7520e8326c1f6b75e022b15466961</td></tr>
        <tr><td>Fragment 2/5</td><td>62d054630e0f0d2b094ea509dabfd88f0e1353b6e4b32faf2dc2e3450d9ba52d8d2b1baa25d375008549cec106a53fc227fdb47eeaeede60720d2ad3cff05c3f</td></tr>
        <tr><td>Fragment 3/5</td><td>6d255d65c111fbb69a063c09441ee0ffe5b090967d41fd24f9fab76edebd06a2c741070b2a420c94b1cb01e00e5e5cdc067f94e7430ff187a31db785d7abdd6b</td></tr>
        <tr><td>Fragment 4/5</td><td>2d515c82dd51e724d4de060b0e4cb67599b83e7c5a0434c020e339722a3d2e46e71465a3b937d37ba913daf3a8242e8a6ca39b2e2c6e1f4cd854c7f08a87f357</td></tr>
        <tr><td>Fragment 5/5</td><td>62402262d720672c1882916c1d8f5a0af10c1d4531ab0673b4bc2206a8d32e6875358a3dfccd8359d3c4e3c1b5aba43ce32112823ed216831333d82b2754101e</td></tr>
    </table>
    <script>function refresh() { alert('🔄 Strona została odświeżona...   chyba'); }</script>
</body>
</html>
EOF

    mkdir -p /var/www/html/status
    cat > /var/www/html/status/index.html << 'EOF'
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <title>Service Status</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }
        .status-table { width: 100%; max-width: 800px; margin: 20px auto; border-collapse: collapse; }
        .status-table th, .status-table td { border: 1px solid #30363d; padding: 12px; text-align: left; }
        .status-table th { background: #161b22; }
        .status-ok { color: #3fb950; }
        .status-error { color: #f85149; }
        .status-warning { color: #d29922; }
        .status-table td[onclick] { cursor: pointer; }
        .status-table td[onclick]:hover { background: #0f1620; }
        .hint { font-size: 0.7em; color: #8b949e; text-align: center; margin-top: 30px; }
        .details { display: none; background: #161b22; padding: 10px; margin-top: 5px; border-left: 3px solid #d29922; }
        .details_ok { display: none; background: #161b22; padding: 10px; margin-top: 5px; border-left: 3px solid #22d23a; }
        .details_down { display: none; background: #161b22; padding: 10px; margin-top: 5px; border-left: 3px solid #d10d0d; }
    </style>
</head>
<body>
    <h1>🔧 Service Status Dashboard</h1>
    <table class="status-table">
        <tr><th>Service</th><th>Status</th><th>Details</th></tr>
        <tr><td>AWS Connection</td><td class="status-ok" onclick="toggleDetails('aws-details')">✓ ONLINE</td><td>Connected to US-EAST1</td></tr>
        <tr><td>Docker Engine</td><td class="status-warning" onclick="toggleDetails('docker-details')">⚠ WARNING</td><td>Click for details</td></tr>
        <tr><td>Database</td><td class="status-ok" onclick="toggleDetails('db-details')">✓ ONLINE</td><td>PostgreSQL</td></tr>
        <tr><td>Web Server</td><td class="status-ok" onclick="toggleDetails('web-details')">✓ ONLINE</td><td>Apache</td></tr>
        <tr><td>New function</td><td class="status-error" onclick="toggleDetails('newfunc-details')">✗ OFFLINE</td><td>Click for details</td></tr>
    </table>
    <div class="details_ok" id="aws-details">
        <strong>[2025-10-12 21:11:59] [aws.service] [OK]</strong><br>
        <code>
        Info: Connected to AWS US-EAST1 region successfully.<br>
        Systemd service running without issues.<br>       
        No issues detected.<br>
        Last checked: 2024-06-15 10:23:45
        </code>
    </div>
    <div class="details_ok" id="db-details">
        <strong>[2025-10-12 21:11:59] [postgres.service] [OK]</strong><br>
        <code>
        Info: PostgreSQL database is running smoothly.<br>
        Uptime: 72 hours<br>
        Last backup: 2024-06-15 02:00:00
        </code>
    </div>
    <div class="details_ok" id="web-details">
        <strong>[2025-10-12 21:11:59] [apache.service] [OK]</strong><br>
        <code>
        Info: Apache web server is operational.<br>
        Uptime: 120 hours<br>
        Active connections: 45
        </code>
    </div>
    <div class="details" id="docker-details">
        <strong>[2025-11-02 13:42:17] [docker.service] [ERROR]</strong><br>
        <code>
        Component: StorageDriver<br>
        EventID: 0x1A3FB2C<br>
        Code: ERR_STORAGE_DECRYPT_FAIL<br>
        Message: Could not decrypt mounted artifact. Key verification failed — password fragment may be incorrect or truncated.<br>
        <br>
        Context:<br>
        &nbsp;Affected file: https://github.com/Nexti420/WorkInProgrezz/blob/main/PNG.enc<br>
        &nbsp;Decryption attempt:<br>
        &nbsp;&nbsp;Password used: Bob_Majster123<br>
        &nbsp;&nbsp;Key derivation: PBKDF2 (SHA-256)<br>
        &nbsp;&nbsp;Salt (hex): 73616c745f313233<br>
        &nbsp;&nbsp;Iterations: 100000<br>
        &nbsp;&nbsp;Key size: 128 bits (16 bytes)<br>
        &nbsp;&nbsp;Cipher mode: AES-CBC<br>
        &nbsp;&nbsp;IV (hex): 000102030405060708090a0b0c0d0e0f
        </code>
    </div>
    <div class="details_down" id="newfunc-details">
        <strong>[2025-10-31 11:34:25] [python.runtime] [ERROR]</strong><br>
        <code>
        Traceback (most recent call last):<br>
        &nbsp;File "/usr/local/app/decrypt_module.py", line 84, in module<br>
        &nbsp;&nbsp;    result = DecryptFile(passwd="wQgZxauX")<br>
        &nbsp;File "/usr/local/app/decrypt_module.py", line 37, in DecryptFile<br>
        &nbsp;&nbsp;    raise MissingFragmentError("Password fragment incomplete or invalid")<br><br>

        MissingFragmentError: Missing password fragment — unable to complete decryption sequence.<br>
        [INFO] Function initialization failed<br>
        [DETAILS]<br>
        &nbsp;&nbsp;Code: ERR_FUNC_INIT<br>
        &nbsp;&nbsp;Message: Missing dependencies or parameters detected<br>
        &nbsp;&nbsp;Recommended action: Review function setup and ensure all required inputs are provided.
        </code>
    </div>
    <div class="hint" id="SJWtw3p%">💡 ..... + Me</div>
    <script>
        function toggleDetails(data) {
            var d = document.getElementById(data || 'docker-details');
            d.style.display = (d.style.display === 'none' || d.style.display === '') ? 'block' : 'none';
        }
    </script>
</body>
</html>
EOF
    
    cat > /var/www/html/robots.txt << 'EOF'
User-agent: *
Disallow: /admin
Disallow: /backup
Disallow: /config

# If you're reading this, you're on the right track
# Secret hint: vzz3v
# Sometimes the answer is hidden in plain sight
EOF

    mkdir -p /var/www/html/admin
    cat > /var/www/html/admin/index.html << 'EOF'
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin view</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container { text-align: center; }
        h1 { font-size: 3em; margin-bottom: 20px; }
        .link { color: #ffd700; text-decoration: none; font-size: 1.2em; }
        .footer { position: fixed; bottom: 10px; right: 10px; font-size: 0.8em; opacity: 0.3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚧 Work in Progress 🚧</h1>
        <img src="https://raw.githubusercontent.com/Nexti420/WorkInProgrezz/refs/heads/main/html/Shrek_pelen.png" alt="Shrek" />
    </div>
    <div class="footer">Powered by SHA-512</div>
</body>
</html>
EOF

    echo "ErrorDocument 404 /404.html" >> /etc/apache2/apache2.conf
    systemctl enable apache2
    systemctl restart apache2
    log_success "HTTP skonfigurowany"
    
   # 7. Docker Images
    log_info "Budowanie obrazów Docker..."
    
    systemctl restart docker
    sleep 3
    
    mkdir -p /home/devuser/docker-images
    chown -R devuser:devuser /home/devuser/docker-images
    
    # Shrek - podpowiedź
    mkdir -p /home/devuser/docker-images/shrek
    cat > /home/devuser/docker-images/shrek/Dockerfile << 'DEOF'
FROM alpine:latest
CMD ["echo", "Ogry są jak cebule, bo mają warstwy... 🧅"]
DEOF
    chown -R devuser:devuser /home/devuser/docker-images/shrek
    docker build -t shrek:1 /home/devuser/docker-images/shrek 2>&1 | tail -5
    
    # Layer 1 - Fragment 1: Shr3k (base64: U2hyM2s=)
    mkdir -p /home/devuser/docker-images/layer1
    cat > /home/devuser/docker-images/layer1/Dockerfile << 'DEOF'
FROM alpine:latest
RUN echo "U2hyM2s=" > /tmp/secret_part1 && cat /tmp/secret_part1 && rm /tmp/secret_part1
RUN echo "Layer created for configuration"
CMD ["sh", "-c", "echo 'Container initialized'"]
DEOF
    chown -R devuser:devuser /home/devuser/docker-images/layer1
    docker build -t layered:app1 /home/devuser/docker-images/layer1 2>&1 | tail -5
    
    # Layer 2 - Fragment 2: _L0v3s (base64: X0wwdjNz)
    mkdir -p /home/devuser/docker-images/layer2
    cat > /home/devuser/docker-images/layer2/Dockerfile << 'DEOF'
FROM alpine:latest
LABEL secret_fragment="X0wwdjNz"
LABEL description="Application Layer 2"
RUN echo "Setting up environment variables"
CMD ["sh", "-c", "echo 'Service running'"]
DEOF
    chown -R devuser:devuser /home/devuser/docker-images/layer2
    docker build -t layered:app2 /home/devuser/docker-images/layer2 2>&1 | tail -5
    
    # Vault - Fragment 3: _0n10ns (base64: XzBuMTBucw==) + interaktywny skrypt
    log_info "Przygotowywanie obrazu vault z interaktywnym skryptem..."
    
    mkdir -p /home/devuser/docker-images/vault
    
    # Stwórz interaktywny skrypt unlock
    cat > /home/devuser/docker-images/vault/unlock_vault.sh << 'UNLOCK_EOF'
#!/bin/sh
echo "==================================="
echo "    VAULT AUTHENTICATION SYSTEM    "
echo "==================================="
echo ""
echo "Two keys are required to unlock the vault."
echo ""

# Pobierz pierwszy klucz
echo -n "Enter first key: "
read KEY1

# Pobierz drugi klucz
echo -n "Enter second key: "
read KEY2

# Sprawdź oba klucze
if [ "$KEY1" = "Shr3k_L0v3s_0n10ns" ] && [ "$KEY2" = "G1v3" ]; then
    echo ""
    echo "✓ Authentication successful!"
    echo ""
    echo "===== ROOT SSH KEY ====="
    cat /vault/.root_key
    echo ""
    echo "========================"
    echo ""
    echo "Save this key to a file and use: ssh -i keyfile root@IP"
else
    echo ""
    echo "✗ Authentication failed! Access denied."
    exit 1
fi
UNLOCK_EOF
    
    chmod +x /home/devuser/docker-images/vault/unlock_vault.sh
    
    # Skopiuj klucz SSH roota
    cp /root/.ssh/root_key /home/devuser/docker-images/vault/.root_key
    chown devuser:devuser /home/devuser/docker-images/vault/.root_key
    chown devuser:devuser /home/devuser/docker-images/vault/unlock_vault.sh
    
    cat > /home/devuser/docker-images/vault/Dockerfile << 'DEOF'
FROM alpine:latest

COPY .root_key /vault/.root_key
COPY unlock_vault.sh /vault/unlock_vault.sh

RUN chmod +x /vault/unlock_vault.sh && \
    chmod 600 /vault/.root_key

RUN echo "XzBuMTBucw==" > /tmp/final_piece && cat /tmp/final_piece && rm /tmp/final_piece

RUN echo "Vault initialized with two-key authentication"

LABEL hint="Three fragments unite, like layers of an onion. After onions, use what you found in the config."

CMD ["/vault/unlock_vault.sh"]
DEOF
    
    chown -R devuser:devuser /home/devuser/docker-images/vault
    docker build -t vault:secure /home/devuser/docker-images/vault 2>&1 | tail -5
    
    log_success "Obrazy Docker utworzone"
    
    log_info "Konfiguracja ograniczonego dostępu do Dockera dla devuser..."
    
    gpasswd -d devuser docker 2>/dev/null || true
    
    # Utwórz katalog na wrapper scripts
    mkdir -p /usr/local/bin/docker-restricted
    
    # Wrapper: docker-history
    cat > /usr/local/bin/docker-restricted/docker-history << 'WRAPPER_HISTORY'
#!/bin/bash
if [ $# -eq 0 ]; then
    echo "Usage: docker-history <image>"
    echo "Analyze image layers and build history"
    exit 1
fi
IMAGE="$1"
if ! docker image inspect "$IMAGE" &>/dev/null; then
    echo "Error: Image '$IMAGE' not found"
    echo "Available images:"
    docker images --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}"
    exit 1
fi
echo "=== Image History for: $IMAGE ==="
docker history --no-trunc "$IMAGE"
WRAPPER_HISTORY
    
    # Wrapper: docker-inspect
    cat > /usr/local/bin/docker-restricted/docker-inspect << 'WRAPPER_INSPECT'
#!/bin/bash
if [ $# -eq 0 ]; then
    echo "Usage: docker-inspect <image>"
    echo "Read image metadata and configuration"
    exit 1
fi
IMAGE="$1"
if ! docker image inspect "$IMAGE" &>/dev/null; then
    echo "Error: Image '$IMAGE' not found"
    echo "Available images:"
    docker images --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}"
    exit 1
fi
echo "=== Image Inspection for: $IMAGE ==="
docker inspect "$IMAGE"
WRAPPER_INSPECT
    
    # Wrapper: docker-images
    cat > /usr/local/bin/docker-restricted/docker-images << 'WRAPPER_IMAGES'
#!/bin/bash
echo "=== Available Docker Images ==="
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedSince}}"
WRAPPER_IMAGES
    
    # Wrapper: docker-run
    cat > /usr/local/bin/docker-restricted/docker-run << 'WRAPPER_RUN'
#!/bin/bash
if [ $# -eq 0 ]; then
    echo "Usage: docker-run <image> [args...]"
    echo ""
    echo "Run containers with security restrictions:"
    echo "  • No privileged mode"
    echo "  • No host network"
    echo "  • Limited capabilities"
    echo "  • Read-only root filesystem"
    exit 1
fi
IMAGE="$1"
shift
ARGS="$@"
if ! docker image inspect "$IMAGE" &>/dev/null; then
    echo "Error: Image '$IMAGE' not found"
    docker images --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}"
    exit 1
fi
DOCKER_OPTS=(
    --rm --interactive --tty
    --network none
    --cap-drop=ALL --cap-add=CHOWN --cap-add=SETUID --cap-add=SETGID
    --security-opt=no-new-privileges
    --read-only --tmpfs /tmp
    --memory=512m --cpus=1
)
echo "=== Running container: $IMAGE ==="
echo "Security restrictions applied ✓"
exec docker run "${DOCKER_OPTS[@]}" "$IMAGE" $ARGS
WRAPPER_RUN
    
    # Ustaw uprawnienia
    chmod 755 /usr/local/bin/docker-restricted/docker-*
    
    # Konfiguracja sudo
    cat > /etc/sudoers.d/devuser-docker << 'SUDO_CONFIG'
Cmnd_Alias DOCKER_HISTORY = /usr/local/bin/docker-restricted/docker-history *
Cmnd_Alias DOCKER_INSPECT = /usr/local/bin/docker-restricted/docker-inspect *
Cmnd_Alias DOCKER_IMAGES = /usr/local/bin/docker-restricted/docker-images
Cmnd_Alias DOCKER_RUN = /usr/local/bin/docker-restricted/docker-run *
devuser ALL=(root) NOPASSWD: DOCKER_HISTORY, DOCKER_INSPECT, DOCKER_IMAGES, DOCKER_RUN
devuser ALL=(ALL) !ALL, (root) NOPASSWD: DOCKER_HISTORY, DOCKER_INSPECT, DOCKER_IMAGES, DOCKER_RUN
SUDO_CONFIG
    
    chmod 440 /etc/sudoers.d/devuser-docker
    visudo -c -f /etc/sudoers.d/devuser-docker
    
    # Dodaj aliasy do .bashrc devusera
    cat >> /home/devuser/.bashrc << 'BASHRC_ALIASES'

# ============================================
# Docker Restricted Commands
# ============================================
alias docker-history='sudo /usr/local/bin/docker-restricted/docker-history'
alias docker-inspect='sudo /usr/local/bin/docker-restricted/docker-inspect'
alias docker-images='sudo /usr/local/bin/docker-restricted/docker-images'
alias docker-run='sudo /usr/local/bin/docker-restricted/docker-run'

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║  Available Docker Commands (restricted)                ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "  • docker-history <image>     - Analyze image layers"
echo "  • docker-inspect <image>     - Read image metadata"
echo "  • docker-images              - List images"
echo "  • docker-run <image> [args]  - Run containers (restricted)"
echo ""
BASHRC_ALIASES
    
    chown devuser:devuser /home/devuser/.bashrc
    
    log_success "Ograniczony dostęp do Dockera skonfigurowany dla devuser"
    
    # 8. Systemd Service (GŁÓWNA PODATNOŚĆ - ESKALACJA DO ROOT)
    log_info "Konfiguracja podatnej usługi systemd..."
    
    mkdir -p /opt/monitor
    cat > /opt/monitor/check_aws.sh << 'SEOF'
#!/bin/bash
if [ -f /etc/monitor/aws.env ]; then
    source /etc/monitor/aws.env
fi
AWS_ENDPOINT=${AWS_ENDPOINT:-"https://aws.amazon.com"}
echo "[$(date)] Checking AWS connectivity..."
curl -s --connect-timeout 5 "$AWS_ENDPOINT" > /dev/null
if [ $? -eq 0 ]; then
    echo "[$(date)] AWS connection: OK"
    exit 0
else
    echo "[$(date)] AWS connection: FAILED"
    exit 1
fi
SEOF
    chmod +x /opt/monitor/check_aws.sh
    
    mkdir -p /etc/monitor
    cat > /etc/monitor/aws.env << 'SEOF'
AWS_ENDPOINT="https://aws.amazon.com"
AWS_REGION="eu-central-1"
SEOF
    chown root:ftpuser /etc/monitor/aws.env
    chmod 664 /etc/monitor/aws.env
    
    cat > /etc/systemd/system/aws-monitor.service << 'SEOF'
[Unit]
Description=AWS Connectivity Monitor
After=network.target

[Service]
Type=oneshot
EnvironmentFile=/etc/monitor/aws.env
ExecStart=/opt/monitor/check_aws.sh
User=root
StandardOutput=journal

[Install]
WantedBy=multi-user.target
SEOF
    
    cat > /etc/systemd/system/aws-monitor.timer << 'SEOF'
[Unit]
Description=Run AWS Monitor every 5 minutes
Requires=aws-monitor.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Unit=aws-monitor.service

[Install]
WantedBy=timers.target
SEOF
    
    systemctl daemon-reload
    systemctl enable aws-monitor.timer
    systemctl start aws-monitor.timer
    log_success "Usługa systemd skonfigurowana"
    
    # 9. GRUB
    log_info "Zabezpieczanie GRUB..."
    GRUB_HASH=$(echo -e "GrubSecure123!\nGrubSecure123!" | grub-mkpasswd-pbkdf2 2>/dev/null | grep "grub.pbkdf2" | awk '{print $NF}')
    
    if ! grep -q "set superusers=" /etc/grub.d/40_custom; then
        cat >> /etc/grub.d/40_custom << EOF

set superusers="grubadmin"
password_pbkdf2 grubadmin $GRUB_HASH
EOF
    fi
    
    update-grub 2>/dev/null || grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null
    chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
    log_success "GRUB zabezpieczony"
    
    # 10. Flaga
    cat > /root/flag.txt << 'EOF'
🎉 CONGRATULATIONS! 🎉

You've successfully completed the Pentesty CTF challenge!

root_passwd -> B6D5qTvFGKgNq$

Your path to root:
1. SSH reconnaissance (banner hint)
2. FTP exploitation (authorized_keys injection)
3. Systemd service misconfiguration (escalation to root)

Alternative path:
1. GitHub enumeration (encrypted files in repository)
2. Git history analysis (old GPG password)
3. Decrypt files to get devuser password fragments
4. Docker image forensics (assemble onion password)
5. Decrypt root SSH key with two-layer encryption
6. SSH as root

Well done, pentester! 🔐
EOF
    
    # Oznacz zakończenie
    echo "completed" > "$MARKER_FILE"
    #log_success "Konfiguracja zakończona pomyślnie! Flaga znajduje się w /root/flag.txt"
    
    # Podsumowanie
    clear
    log_info ""
    log_info "╔════════════════════════════════════════════════════════╗"
    log_info "║  CTF MACHINE READY                                     ║"
    log_info "║                                                        ║"
    log_info "║  Hasło GRUB:                                           ║"
    log_info "║     Użytkownik: grubadmin                              ║"
    log_info "║     Hasło: GrubSecure123                               ║"
    log_info "║                                                        ║"
    log_info "╚════════════════════════════════════════════════════════╝"
fi
