# Wdrażanie PowerControl do produkcji

## Przegląd

Ten dokument opisuje proces wdrażania PowerControl w środowisku produkcyjnym z fokusem na bezpieczeństwo, niezawodność i skalowanie.

## Pre-deployment checklist

- [ ] Przejrzano i przygotowano `config.yaml`
- [ ] Hasła przechowywane w zmiennych środowiskowych lub .env
- [ ] Certyfikaty SSL przygotowane (dla HTTPS)
- [ ] Backup konfiguracji wykonany
- [ ] Testy wszystkich funkcjonalności zakończone
- [ ] Logi są skonfigurowane
- [ ] Firewall skonfigurowany
- [ ] Plan rollback przygotowany

## Wdrażanie na Raspberry Pi

### 1. Przygotowanie systemu

```bash
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y python3 python3-pip python3-venv git nginx curl

# Tworzenie użytkownika dedykowanego
sudo useradd -m -s /bin/bash powercontrol
sudo usermod -a -G gpio powercontrol  # Dostęp do GPIO
```

### 2. Konfiguracja katalogów

```bash
sudo mkdir -p /opt/powercontrol
sudo mkdir -p /var/log/powercontrol
sudo mkdir -p /var/lib/powercontrol

sudo chown -R powercontrol:powercontrol /opt/powercontrol
sudo chown -R powercontrol:powercontrol /var/log/powercontrol
sudo chown -R powercontrol:powercontrol /var/lib/powercontrol
```

### 3. Instalacja aplikacji

```bash
cd /opt/powercontrol

# Klonowanie repozytorium
sudo -u powercontrol git clone https://github.com/yourusername/PowerControl.git .

# Wirtualne środowisko
sudo -u powercontrol python3 -m venv venv
sudo -u powercontrol venv/bin/pip install --upgrade pip

# Instalacja zależności
sudo -u powercontrol venv/bin/pip install -r requirements.txt
```

### 4. Konfiguracja Systemd

Utwórz `/etc/systemd/system/powercontrol.service`:

```ini
[Unit]
Description=PowerControl Infrastructure Manager
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=powercontrol
WorkingDirectory=/opt/powercontrol
Environment="PATH=/opt/powercontrol/venv/bin"

# Wczytanie zmiennych środowiskowych
EnvironmentFile=/etc/powercontrol/.env

ExecStart=/opt/powercontrol/venv/bin/python3 /opt/powercontrol/main.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/powercontrol/app.log
StandardError=append:/var/log/powercontrol/error.log

# Limity zasobów
CPUQuota=80%
MemoryLimit=256M
MemoryMax=512M

[Install]
WantedBy=multi-user.target
```

Aktywacja:

```bash
sudo systemctl daemon-reload
sudo systemctl enable powercontrol
sudo systemctl start powercontrol
sudo systemctl status powercontrol
```

## Konfiguracja Nginx (Reverse Proxy)

### Bez SSL (development)

Utwórz `/etc/nginx/sites-available/powercontrol`:

```nginx
upstream powercontrol_backend {
    server 127.0.0.1:5000;
}

server {
    listen 80;
    server_name powercontrol.local;

    location / {
        proxy_pass http://powercontrol_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### Z SSL (produkcja)

```nginx
upstream powercontrol_backend {
    server 127.0.0.1:5000;
}

server {
    listen 80;
    server_name powercontrol.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name powercontrol.example.com;

    ssl_certificate /etc/letsencrypt/live/powercontrol.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/powercontrol.example.com/privkey.pem;
    
    # SSL Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://powercontrol_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

Aktywacja:

```bash
sudo ln -s /etc/nginx/sites-available/powercontrol /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Certyfikat SSL z Let's Encrypt

```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot certonly --nginx -d powercontrol.example.com
sudo certbot renew --dry-run  # Test auto-renewal
```

## Konfiguracja Firewall

```bash
# UFW (Uncomplicated Firewall)
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Zezwolenie na SSH
sudo ufw allow 22/tcp

# Zezwolenie na HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Włączenie firewall
sudo ufw enable

# Weryfikacja
sudo ufw status
```

## Monitoring i logi

### Konfiguracja logowania

```yaml
# config.yaml
logging:
  level: "INFO"
  file: "/var/log/powercontrol/app.log"
  max_size_mb: 50
  backup_count: 10
```

### Monitoring logów

```bash
# Śledzenie logów w real-time
tail -f /var/log/powercontrol/app.log

# Ostatnie 100 linii
tail -100 /var/log/powercontrol/app.log

# Wyszukiwanie błędów
grep ERROR /var/log/powercontrol/app.log
```

### Rotacja logów

Utwórz `/etc/logrotate.d/powercontrol`:

```
/var/log/powercontrol/*.log {
    daily
    rotate 10
    compress
    delaycompress
    notifempty
    create 0640 powercontrol powercontrol
    sharedscripts
    postrotate
        systemctl reload powercontrol > /dev/null 2>&1 || true
    endscript
}
```

## Backup i odzyskiwanie

### Backup konfiguracji

```bash
#!/bin/bash
BACKUP_DIR="/backups/powercontrol"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/powercontrol_$DATE.tar.gz \
    /opt/powercontrol/config.yaml \
    /opt/powercontrol/relay_notifications.json \
    --exclude='venv'

# Zachowaj ostatnie 30 backupów
find $BACKUP_DIR -name "powercontrol_*.tar.gz" -mtime +30 -delete
```

Dodaj do crontab:

```bash
0 3 * * * /root/backup_powercontrol.sh
```

### Odzyskiwanie

```bash
tar -xzf /backups/powercontrol/powercontrol_20231215_030000.tar.gz -C /opt/powercontrol/
sudo systemctl restart powercontrol
```

## Aktualizacja aplikacji

```bash
cd /opt/powercontrol
sudo -u powercontrol git pull origin main
sudo -u powercontrol venv/bin/pip install -r requirements.txt
sudo systemctl restart powercontrol
sudo systemctl status powercontrol
```

## Troubleshooting

### Aplikacja nie startuje

```bash
sudo systemctl status powercontrol
sudo journalctl -u powercontrol -n 50
tail -50 /var/log/powercontrol/app.log
```

### Wysokie zużycie CPU/Pamięci

```bash
# Monitorowanie procesów
top -p $(pgrep -f "python3 main.py")

# Sprawdzenie wątków
ps -eLo pid,tid,comm | grep python3
```

### Problemy z GPIO

```bash
# Sprawdzenie dostępu do GPIO
gpio readall

# Sprawdzenie uprawnień
ls -la /dev/gpiomem
ls -la /sys/class/gpio
```

## Metryki Performance

- **Startup time:** ~5-10 sekund
- **Memory usage:** ~150-200MB
- **CPU load:** <5% (idle)
- **Max concurrent connections:** 100+ (z Gunicorn)

## Rekomendacje bezpieczeństwa

1. **Aktualizacja systemu**: `sudo apt-get update && sudo apt-get upgrade`
2. **SSH key only**: Wyłącz logowanie hasłem w SSH
3. **Firewall**: UFW z restrykcyjnymi regułami
4. **HTTPS only**: Wymuś SSL w produkcji
5. **Monitoring**: Ustaw alerty dla błędów aplikacji
6. **Backups**: Codzienne backupy konfiguracji
7. **Secrets**: Używaj zmiennych środowiskowych dla haseł

## Support

W razie problemów:
- Sprawdź logi w `/var/log/powercontrol/app.log`
- Konsultuj dokumentację w `INSTALLATION.md`
- Otwórz issue na GitHubie
