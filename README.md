# PowerControl

Aplikacja do zarządzania zasilaniem i monitorowania urządzeń w sieci – sterowanie przekaźnikami (GPIO na Raspberry Pi), integracja z Proxmox VE, Wake-on-LAN, powiadomienia e-mail oraz prosty interfejs webowy.

## Funkcje

- **Przekaźniki (GPIO)** – sterowanie zasilaniem urządzeń przez Raspberry Pi (gpiozero)
- **Proxmox VE** – sprawdzanie stanu węzłów i maszyn wirtualnych, szybki start VM z przypisaniem do przekaźników
- **Wake-on-LAN** – budzenie komputerów w sieci
- **Monitor (heartbeat)** – okresowy zapis stanu, powiadomienia o starcie/zatrzymaniu aplikacji
- **E-mail** – powiadomienia o zdarzeniach (start, shutdown, zdarzenia przekaźników)
- **Interfejs webowy** – zarządzanie przekaźnikami, lista VM, status komputerów

## Wymagania

- Python 3.10+
- Raspberry Pi (dla GPIO) lub uruchomienie bez sprzętu (moduły relay/switch będą opcjonalne)
- Opcjonalnie: serwer Proxmox VE, konfiguracja SMTP do e-maili

## Instalacja

### 1. Klonowanie repozytorium

```bash
git clone https://github.com/TWOJ_USER/repo-name.git
cd powerControl
```

### 2. Środowisko wirtualne i zależności

```bash
python3 -m venv venv
source venv/bin/activate   # Linux/macOS
# venv\Scripts\activate   # Windows

pip install -r requirements.txt
```

### 3. Konfiguracja

Skopiuj plik przykładowy i uzupełnij własnymi danymi:

```bash
cp config.example.yaml config.yaml
# Edytuj config.yaml – adresy IP, hasła, tokeny Proxmox, ustawienia e-mail itd.
```

**Ważne:** Plik `config.yaml` nie jest commitowany do repozytorium (zawiera hasła i dane wrażliwe). Użyj `config.example.yaml` jako szablonu.

Wybrane wartości można nadpisać zmiennymi środowiskowymi w formacie `POWERCONTROL__SEKCJA__KLUCZ`, np.:

- `POWERCONTROL__EMAIL__PASSWORD` – hasło do skrzynki e-mail
- `POWERCONTROL__PROXMOX__TOKEN_VALUE` – token API Proxmox

### 4. Uruchomienie

```bash
python main.py
```

Aplikacja uruchomi serwer HTTP (domyślnie port 5000). Otwórz w przeglądarce adres podany w konfiguracji (np. `http://localhost:5000`).

## Uruchomienie jako usługa systemd (Linux)

```bash
sudo cp service/powerControl.service /etc/systemd/system/
# Dostosuj ścieżki w pliku .service jeśli potrzeba (WorkingDirectory, ExecStart)
sudo systemctl daemon-reload
sudo systemctl enable powerControl
sudo systemctl start powerControl
sudo systemctl status powerControl
```

## Struktura projektu

```
powerControl/
├── main.py              # Punkt wejścia, lifecycle aplikacji
├── config.yaml          # Twoja konfiguracja (nie w repo – tworzona z config.example.yaml)
├── config.example.yaml  # Szablon konfiguracji
├── requirements.txt
├── app/
│   ├── config.py        # Ładowanie config.yaml i zmiennych środowiskowych
│   ├── web.py           # Aplikacja Flask, interfejs webowy
│   ├── relay.py         # Sterowanie przekaźnikami GPIO
│   ├── proxmox.py       # Integracja z Proxmox API
│   ├── monitor.py       # Heartbeat, powiadomienia start/shutdown
│   ├── emailer.py       # Wysyłka e-maili
│   └── logger.py
├── templates/           # Szablony HTML
├── static/              # Pliki statyczne (favicon itd.)
├── service/             # Unit systemd
└── logs/                # Katalog na logi (tworzony przy pierwszym uruchomieniu)
```

## Licencja

Możesz dodać plik LICENSE (np. MIT, GPL) zgodnie z wyborem licencji projektu.
