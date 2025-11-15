# Instalacja i konfiguracja PowerControl

## Wymagania systemowe

- **System operacyjny:** Linux (Debian/Ubuntu) lub Raspberry Pi OS
- **Python:** 3.8 lub wyższa wersja
- **Dostęp root/sudo:** Wymagany do obsługi GPIO
- **Połączenie sieciowe:** Do komunikacji z Proxmox i hostami

## Instalacja zależności systemowych

### Na Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv python3-dev
```

### Na Raspberry Pi OS

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv python3-dev libffi-dev libssl-dev
```

## Instalacja aplikacji

### 1. Klonowanie repozytorium

```bash
git clone https://github.com/yourusername/PowerControl.git
cd PowerControl
```

### 2. Tworzenie wirtualnego środowiska

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instalacja zależności Python

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

## Konfiguracja

### Przygotowanie pliku konfiguracji

```bash
cp config.example.yaml config.yaml
```

### Struktura config.yaml

#### Sekcja Web

```yaml
web:
  host: "0.0.0.0"      # IP do nasłuchiwania (0.0.0.0 = wszystkie interfejsy)
  port: 5000           # Port aplikacji
  debug: false         # Tryb debug (tylko dla development)
  secret_key: "change-me-to-random-string"  # Tajny klucz sesji
```

#### Sekcja Email (opcjonalna)

```yaml
email:
  enabled: true
  server: "smtp.gmail.com"
  port: 465
  use_tls: true
  from_addr: "your-email@gmail.com"
  password: "your-app-password"        # Hasło aplikacji (nie zwykłe hasło!)
  to_addrs:
    - "admin@example.com"
    - "user2@example.com"
  sender_name: "PowerControl"
```

**Uwaga dla Gmail:** Użyj [hasła aplikacji](https://support.google.com/accounts/answer/185833), a nie zwykłego hasła do konta.

#### Sekcja Przekaźników GPIO

```yaml
relay_pins:        # Numery GPIO dla przekaźników
  - 17
  - 27
  - 22

switch_pins: []    # Piny dla przycisków (opcjonalnie)
```

#### Sekcja Proxmox

```yaml
proxmox:
  enabled: true
  host: "192.168.1.10"
  port: 8006
  user: "root@pam"              # Użytkownik Proxmox
  password: "your-proxmox-password"
  verify_ssl: false             # Ustaw na true w produkcji
  timeout: 10
```

#### Sekcja Monitoring

```yaml
monitor:
  enabled: true
  heartbeat_interval: 30        # Sekundy między heartbeatami
  heartbeat_file: "/tmp/powercontrol_heartbeat.json"
  max_hosts_per_request: 10     # Liczba hostów do jednoczesnego monitorowania
  thread_pool_size: 5
```

#### Sekcja Logowania

```yaml
logging:
  level: "INFO"                 # DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: "logs/powercontrol.log"
  max_size_mb: 10
  backup_count: 5
```

### Przykładowa pełna konfiguracja

Zobacz `config.example.yaml` w repozytorium.

## Uruchomienie

### Ręczne uruchomienie

```bash
python3 main.py
```

Aplikacja będzie dostępna pod: `http://localhost:5000`

### Uruchomienie w tle

```bash
nohup python3 main.py > logs/powercontrol.log 2>&1 &
```

### Uruchomienie z Systemd (zalecane)

Utwórz plik `/etc/systemd/system/powercontrol.service`:

```ini
[Unit]
Description=PowerControl Infrastructure Manager
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/PowerControl
ExecStart=/home/pi/PowerControl/venv/bin/python3 /home/pi/PowerControl/main.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/powercontrol/app.log
StandardError=append:/var/log/powercontrol/error.log

[Install]
WantedBy=multi-user.target
```

Włączenie:

```bash
sudo systemctl daemon-reload
sudo systemctl enable powercontrol
sudo systemctl start powercontrol
sudo systemctl status powercontrol
```

## Bezpieczeństwo

### Zmienne środowiskowe (rekomendowane dla produkcji)

Zamiast przechowywania haseł w `config.yaml`, użyj zmiennych środowiskowych:

```bash
export POWERCONTROL_EMAIL_PASSWORD="your-password"
export POWERCONTROL_PROXMOX_PASSWORD="your-password"
```

W kodzie:

```python
email_password = os.getenv('POWERCONTROL_EMAIL_PASSWORD', 'default')
```

### Reverse Proxy z SSL

Dla produkcji, ustaw Nginx reverse proxy:

```nginx
server {
    listen 443 ssl http2;
    server_name powercontrol.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### UFW Firewall

```bash
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 5000/tcp  # PowerControl
sudo ufw enable
```

## Aktualizacja aplikacji

```bash
cd PowerControl
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart powercontrol
```

## Rozwiązywanie problemów

### GPIO nie działa

- Upewnij się, że uruchamiasz jako root lub użytkownik w grupie `gpio`
- Sprawdź numery pinów w konfiguracji
- `gpio readall` - wyświetl dostępne piny

### Email nie działa

- Sprawdź logi: `tail -f logs/powercontrol.log`
- Testujesz na Gmailu? Użyj hasła aplikacji, nie zwykłego hasła
- Sprawdź dostęp do serwera SMTP: `telnet smtp.gmail.com 465`

### Proxmox nie łączy się

- Sprawdź poprawność IP i portu Proxmox
- Weryfikuj credentials użytkownika
- `verify_ssl: false` może być potrzebny dla certyfikatów self-signed

## Wsparcie

Jeśli napotkasz problem:

1. Sprawdź logi w `logs/powercontrol.log`
2. Otwórz issue na GitHubie z logami błędu
3. Załącz konfigurację (bez haseł!)
