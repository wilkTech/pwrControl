# PowerControl

Zaawansowany system zarządzania infrastrukturą sieciową z obsługą przekaźników GPIO, hostów sieciowych i wirtualizacji Proxmox.

## Funkcjonalności

- **Zarządzanie przekaźnikami** - Sterowanie przekaźnikami z GPIO w time-realtime
- **Monitoring hostów** - Śledzenie statusu i dostępności urządzeń w sieci
- **Integracja Proxmox** - Kontrola maszyn wirtualnych i systemów
- **Interfejs webowy** - Responsywny dashboard z aktualizacjami live
- **Powiadomienia email** - Automatyczne alerty o zmianach statusu
- **Heartbeat monitoring** - Kontrola zdrowia aplikacji

## Wymagania

- Python 3.8+
- Flask
- PyYAML
- Proxmoxer
- Paramiko
- WakeOnLan
- gpiozero (opcjonalnie, tylko dla GPIO)

## Instalacja

### Szybki start

```bash
# 1. Klonuj repozytorium
git clone https://github.com/yourusername/PowerControl.git
cd PowerControl

# 2. Utwórz wirtualne środowisko
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# lub
venv\Scripts\activate  # Windows

# 3. Zainstaluj zależności
pip install -r requirements.txt

# 4. Skopiuj i edytuj konfigurację
cp config.example.yaml config.yaml
nano config.yaml

# 5. Uruchom aplikację
python3 main.py
```

### Bardziej szczegółowe instrukcje

Dla szczegółowych instrukcji instalacji i konfiguracji, zobacz [INSTALLATION.md](docs/INSTALLATION.md).

## Konfiguracja

Aplikacja wymaga pliku `config.yaml`. Przykład zawiera wszystkie wymagane opcje:

```yaml
web:
  host: "0.0.0.0"
  port: 5000
  debug: false

email:
  enabled: true
  server: "smtp.gmail.com"
  port: 465
  from_addr: "your-email@gmail.com"
  password: "your-app-password"
  to_addrs:
    - "recipient@example.com"

relay_pins:
  - 17
  - 27

proxmox:
  host: "192.168.1.10"
  user: "root@pam"
  password: "your-password"

monitor:
  enabled: true
  heartbeat_interval: 30
```

Pełny przewodnik konfiguracji: [CONFIGURATION.md](docs/CONFIGURATION.md)

## Użytkowanie

Po uruchomieniu aplikacja będzie dostępna pod adresem:

```
http://localhost:5000
```

### Funkcje dashboardu

- **Sekcja Przekaźników** - Włączanie/wyłączanie przekaźników i zarządzanie powiadomieniami
- **Sekcja Hostów** - Wyświetlanie statusu urządzeń w sieci
- **Sekcja Proxmox** - Monitoring maszyn wirtualnych i hostów hypervisora

## Struktura projektu

```
PowerControl/
├── main.py                    # Główny punkt wejścia
├── requirements.txt           # Zależności
├── config.example.yaml        # Przykładowa konfiguracja
├── app/
│   ├── config.py             # Moduł konfiguracji
│   ├── logger.py             # System logowania
│   ├── web.py                # Aplikacja Flask
│   ├── emailer.py            # Wysyłanie emaili
│   ├── relay.py              # Kontrola GPIO
│   ├── monitor.py            # Monitoring
│   └── proxmox.py            # API Proxmox
├── templates/
│   └── index.html            # Interfejs webowy
├── static/
│   └── favicon.png           # Ikona
└── docs/                      # Dokumentacja
```

## Licencja

Projekt jest dostępny na licencji [MIT](LICENSE).

## Wkład

Aby wnieść wkład w projekt:

1. Forkuj repozytorium
2. Utwórz gałąź dla swojej funkcji (`git checkout -b feature/AmazingFeature`)
3. Zatwierdź zmiany (`git commit -m 'Add AmazingFeature'`)
4. Wypchnij do gałęzi (`git push origin feature/AmazingFeature`)
5. Otwórz Pull Request

## Wsparcie

Jeśli masz pytania lub problemy, otwórz issue na GitHubie.

---

**Status:** Funkcjonalny (wersja alpha)  
**Ostatnia aktualizacja:** 2025-11-15
