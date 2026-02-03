# PowerControl

**PowerControl** to aplikacja do centralnego zarządzania zasilaniem i monitorowania urządzeń w sieci lokalnej. Umożliwia sterowanie przekaźnikami podłączonymi do Raspberry Pi (GPIO), integrację z klastrem Proxmox VE, budzenie komputerów (Wake-on-LAN), zdalne wyłączanie/restart hostów oraz powiadomienia e-mail o zdarzeniach. Dostęp do wszystkich funkcji odbywa się przez prosty interfejs webowy (dashboard).

Projekt jest przeznaczony m.in. do:
- sterowania zasilaniem serwerów, stacji roboczych i urządzeń w racku,
- szybkiego włączania/wyłączania maszyn wirtualnych Proxmox z przypisaniem do konkretnych przekaźników,
- monitorowania „serca bicia” aplikacji (heartbeat) i wykrywania nieplanowanych przerw w pracy (np. awaria zasilania),
- otrzymywania e-maili o starcie/zatrzymaniu aplikacji oraz o zdarzeniach przekaźników.

---

## Spis treści

- [Funkcje](#funkcje)
- [Wymagania](#wymagania)
- [Instalacja](#instalacja)
- [Konfiguracja](#konfiguracja)
- [Uruchomienie](#uruchomienie)
- [Interfejs webowy i API](#interfejs-webowy-i-api)
- [Struktura projektu](#struktura-projektu)
- [Bezpieczeństwo i dobre praktyki](#bezpieczeństwo-i-dobre-praktyki)
- [Rozwiązywanie problemów](#rozwiązywanie-problemów)
- [Licencja](#licencja)

---

## Funkcje

### Sterowanie przekaźnikami (GPIO)

- Sterowanie wieloma przekaźnikami podłączonymi do pinów GPIO Raspberry Pi (biblioteka **gpiozero**).
- Konfigurowalne piny dla przekaźników (`relay_pins`) oraz przycisków fizycznych (`switch_pins`).
- Po utracie zasilania przekaźniki domyślnie przechodzą w stan wyłączony (bezpieczne zachowanie).
- Opcjonalna logika zależności między przekaźnikami (np. przekaźnik „główny” włącza się automatycznie, gdy włączone są inne).
- Powiadomienia e-mail o długotrwałym włączeniu przekaźnika (konfigurowalny próg czasu, np. 4 h) z możliwością wyłączenia w konfiguracji (`enable_relay_event_emails`).
- Stan powiadomień zapisywany w pliku (np. `relay_notifications.json`), aby uniknąć duplikatów.

### Integracja z Proxmox VE

- Połączenie z klastrem Proxmox przez API (token lub hasło).
- Wyświetlanie listy węzłów i maszyn wirtualnych oraz ich stanu (włączone/wyłączone).
- Uruchamianie i zatrzymywanie VM oraz węzłów z poziomu interfejsu.
- **Szybki start (Quick Start)** – przypisanie wybranych VM do konkretnych przekaźników: jedna akcja włącza przekaźnik i startuje skonfigurowane VM na danym węźle (z opcjonalnym sprawdzeniem, czy wymagane przekaźniki są włączone).
- Opcjonalne sprawdzanie dostępności węzłów (ping, port) oraz cooldown po błędach, aby nie przeciążać API.
- Konfiguracja wielu węzłów, adresów MAC (np. do WOL), credentialy SSH do węzłów (fallback).

### Komputery i hosty (Wake-on-LAN, shutdown, reboot)

- Definicja hostów w konfiguracji: nazwa, adres MAC, IP, przypisany przekaźnik, dane logowania (Windows/Linux).
- **Wake-on-LAN** – budzenie komputerów z poziomu panelu.
- **Shutdown / Reboot** – zdalne wyłączanie lub restart przez SSH (Linux) lub (w przyszłości) protokoły Windows.
- Sprawdzanie „czy host żyje” (ping) z uwzględnieniem stanu przekaźnika – jeśli zasilanie jest wyłączone, host nie jest pingowany.
- Lista hostów z aktualnym statusem (online/offline/unknown) w API i na stronie.

### Monitor (heartbeat) i powiadomienia o starcie/zatrzymaniu

- Okresowy zapis stanu aplikacji do pliku (np. `logs/last_heartbeat.json`) w konfigurowalnym interwale (np. 60 s).
- Wykrywanie **graceful shutdown** – przy prawidłowym zatrzymaniu (SIGINT/SIGTERM) aplikacja zapisuje flagę, dzięki czemu przy następnym starcie nie wysyła fałszywego alarmu „awaria zasilania”.
- Przy starcie: analiza poprzedniego heartbeat (czy był graceful shutdown, szacowany czas niedostępności).
- E-mail z powiadomieniem o **starcie** aplikacji (opcjonalnie, `enable_startup_notifications`).
- E-mail z powiadomieniem o **zatrzymaniu** aplikacji (opcjonalnie, `enable_shutdown_notifications`).

### Powiadomienia e-mail

- Wysyłka przez SMTP (np. Gmail, własny serwer).
- Powiadomienia: start aplikacji, shutdown aplikacji, zdarzenia przekaźników (włączone na długi czas), ewentualnie alerty z monitora.
- Konfigurowalne: adres nadawcy, odbiorcy, prefix tematu, limit wysyłek na minutę, retry.
- Hasło do skrzynki można przekazać przez zmienną środowiskową `POWERCONTROL__EMAIL__PASSWORD` zamiast wpisywać w `config.yaml`.

### Interfejs webowy (Flask)

- Jedna strona – **dashboard** z sekcjami: przekaźniki, komputery/hosty, Proxmox (VM, węzły), usługi systemd, opcjonalnie Docker.
- Włączanie/wyłączanie przekaźników, Quick Start / Quick Shutdown dla VM, Wake, Shutdown, Reboot dla hostów.
- Endpoint **Server-Sent Events** (`/events`) do odświeżania stanu w czasie rzeczywistym (np. stan przekaźników, listy VM).
- Endpoint `/healthz` do sprawdzania żywotności (np. load balancer, monitoring).
- Udostępnianie logów aplikacji przez endpoint `/logs` (ostrożnie w środowisku produkcyjnym – dostęp do logów).

---

## Wymagania

- **Python** 3.10 lub nowszy
- **Raspberry Pi** (z Linuxem) – do sterowania GPIO; bez Pi aplikacja uruchomi się, ale moduł przekaźników będzie nieaktywny (mock)
- Opcjonalnie:
  - **Proxmox VE** – do zarządzania VM i węzłami
  - Serwer **SMTP** – do powiadomień e-mail
  - **SSH** (paramiko) – do zdalnego shutdown/reboot hostów
  - **Wake-on-LAN** – do budzenia komputerów

Zależności projektu są w pliku `requirements.txt` (Flask, PyYAML, gpiozero, proxmoxer, wakeonlan, paramiko, requests).

---

## Instalacja

### 1. Klonowanie repozytorium

```bash
git clone https://github.com/TWOJ_USER/NAZWA_REPO.git
cd powerControl
```

(Zamień `TWOJ_USER` i `NAZWA_REPO` na swoje dane.)

### 2. Środowisko wirtualne i zależności

```bash
python3 -m venv venv
source venv/bin/activate   # Linux/macOS
# venv\Scripts\activate    # Windows

pip install -r requirements.txt
```

### 3. Konfiguracja

Skopiuj plik przykładowy i uzupełnij własnymi danymi:

```bash
cp config.example.yaml config.yaml
# Edytuj config.yaml – adresy IP, hasła, tokeny Proxmox, e-mail itd.
```

**Ważne:** Plik `config.yaml` nie jest commitowany do repozytorium (zawiera hasła i dane wrażliwe). Zawsze używaj `config.example.yaml` jako szablonu i trzymaj prawdziwy `config.yaml` tylko lokalnie.

---

## Konfiguracja

Główny plik konfiguracyjny to **YAML** (`config.yaml`). Przykład struktury znajduje się w **config.example.yaml**. Najważniejsze sekcje:

| Sekcja / klucz | Opis |
|----------------|------|
| `log_path`, `log_level` | Ścieżka do pliku logów i poziom (INFO/DEBUG). |
| `host`, `port` | Adres i port serwera HTTP (np. `0.0.0.0:5000`). |
| `heartbeat_interval_s`, `heartbeat_file` | Interwał zapisu heartbeat (s) i plik stanu. |
| `enable_startup_notifications`, `enable_shutdown_notifications` | Powiadomienia e-mail o starcie/zatrzymaniu aplikacji. |
| `enable_relay_event_emails` | Powiadomienia o zdarzeniach przekaźników (długie włączenie). |
| `proxmox` | Węzły (`nodes`), MAC (`nodes_mac`), credentialy (`node_credentials`, `user`, `token_name`, `token_value`), przypisanie VM do przekaźników (`quick_start_vms`, `nodes_relay`), timeout, cooldown. |
| `email` | Serwer SMTP, port, adres, hasło, odbiorcy, SSL/STARTTLS. |
| `computers` | Hosty: `relay`, `MAC`, `IP`, `OS`, `Username`, `Password` (do zdalnego shutdown/reboot). |
| `relay_pins`, `switch_pins` | Listy pinów GPIO dla przekaźników i przycisków. |
| `services` | Opcjonalna lista usług systemd do wyświetlania/sterowania z panelu. |

### Nadpisywanie przez zmienne środowiskowe

Wartości można nadpisać zmiennymi w formacie **`POWERCONTROL__SEKCJA__KLUCZ`** (wielokrotne zagnieżdżenie przez `__`). Przykłady:

- `POWERCONTROL__EMAIL__PASSWORD` – hasło do skrzynki e-mail
- `POWERCONTROL__PROXMOX__TOKEN_VALUE` – token API Proxmox
- `POWERCONTROL__HOST` – adres bindowania serwera (np. `0.0.0.0`)
- `POWERCONTROL__PORT` – port (np. `5000`)

Dzięki temu hasła i tokeny można trzymać poza plikiem (np. w systemd, kontenerze, CI).

---

## Uruchomienie

### Uruchomienie ręczne

```bash
python main.py
```

Serwer HTTP wystartuje na adresie i porcie z konfiguracji (domyślnie np. `http://0.0.0.0:5000`). Otwórz w przeglądarce adres maszyny (np. `http://10.30.25.35:5000`).

### Uruchomienie jako usługa systemd (Linux)

```bash
sudo cp service/powerControl.service /etc/systemd/system/
# Opcjonalnie: edytuj WorkingDirectory i ExecStart (ścieżka do Pythona i main.py)
sudo systemctl daemon-reload
sudo systemctl enable powerControl
sudo systemctl start powerControl
sudo systemctl status powerControl
```

Logi z usługi: `journalctl -u powerControl -f`.

---

## Interfejs webowy i API

### Strona główna

- **`/`** – dashboard: przekaźniki, hosty, VM Proxmox, Quick Start/Shutdown, usługi, logi.

### Przekaźniki

- **POST** `/relay/<id>/on` – włącz przekaźnik
- **POST** `/relay/<id>/off` – wyłącz przekaźnik
- **POST** `/relay/<id>/notify` – ustaw/zeruj powiadomienie dla przekaźnika
- **GET** `/status` – stan wszystkich przekaźników
- **POST** `/allon` – włącz wszystkie (używać z rozwagą)
- **POST** `/alloff` – wyłącz wszystkie

### Komputery / hosty

- **GET** `/hosts/list` – lista hostów z konfiguracji + status (online/offline) i powiązany przekaźnik
- **POST** `/hosts/<id>/wake` – Wake-on-LAN
- **POST** `/hosts/<id>/shutdown` – zdalne wyłączenie
- **POST** `/hosts/<id>/reboot` – zdalny restart
- **GET/POST** `/hosts/<id>/ping` – sprawdzenie dostępności (ping)

### Proxmox

- **GET** `/proxmox/vms` – lista VM (z węzłów skonfigurowanych w `vm_fetch_relays`)
- **GET** `/proxmox/vm/ips` – adresy IP VM (jeśli dostępne)
- **POST** `/proxmox/vm/action` – akcja na VM (start/stop itd.)
- **POST** `/proxmox/node/action` – akcja na węźle
- **POST** `/relay/<id>/quick_start` – Quick Start: włączenie przekaźnika + start skonfigurowanych VM
- **POST** `/relay/<id>/quick_shutdown` – Quick Shutdown: zatrzymanie VM + opcjonalnie wyłączenie przekaźnika z opóźnieniem
- **GET/POST** `/quick_start/choice` – wybór VM do Quick Start (zapisywany w pliku)

### Usługi i Docker

- **GET** `/services/list` – lista usług systemd z konfiguracji
- **POST** `/services/<nazwa>/start|stop|restart` – akcja na usłudze
- **GET** `/services/<nazwa>/status` – status usługi
- **GET** `/docker/containers` – lista kontenerów (jeśli endpoint włączony)
- **POST** `/docker/containers/<id>/start|stop` – akcja na kontenerze

### Inne

- **GET** `/events` – strumień SSE (Server-Sent Events) do odświeżania stanu w czasie rzeczywistym
- **GET** `/healthz` – health check (np. dla load balancera)
- **GET** `/logs` – podgląd logów aplikacji (uważaj w produkcji – dostęp do treści logów)

---

## Struktura projektu

```
powerControl/
├── main.py                 # Punkt wejścia, lifecycle (PowerControlApp), sygnały, kolejność start/stop
├── config.yaml             # Twoja konfiguracja (NIE w repo – tworzona z config.example.yaml)
├── config.example.yaml     # Szablon konfiguracji bez danych wrażliwych
├── requirements.txt
├── app/
│   ├── config.py           # Ładowanie config.yaml + nadpisywanie ze zmiennych POWERCONTROL__*
│   ├── web.py              # Aplikacja Flask, wszystkie endpointy, PowerControlWeb
│   ├── relay.py            # RelayController – GPIO, przekaźniki, przyciski, powiadomienia
│   ├── proxmox.py          # ProxmoxHelper – API Proxmox, WOL, SSH fallback
│   ├── monitor.py          # Monitor – heartbeat, analiza poprzedniej sesji, powiadomienia start/shutdown
│   ├── emailer.py          # Wysyłka e-maili (worker w tle, kolejka)
│   └── logger.py           # Konfiguracja loggera
├── templates/
│   └── index.html          # Jednostronicowy dashboard (HTML/CSS/JS)
├── static/                 # Favicon itd.
├── service/
│   └── powerControl.service  # Unit systemd
└── logs/                   # Katalog na logi i pliki stanu (tworzony przy pierwszym uruchomieniu)
```

Pliki `config.yaml`, `logs/`, `relay_notifications.json`, `last_heartbeat.json`, `quick_start_vm_choices.json` są w `.gitignore` – nie trafiają do repozytorium.

---

## Bezpieczeństwo i dobre praktyki

- **Nie commituj** `config.yaml` – zawiera hasła, tokeny, adresy IP i e-mail. Używaj `config.example.yaml` jako szablonu.
- Hasła i tokeny najlepiej przekazywać przez **zmienne środowiskowe** (`POWERCONTROL__EMAIL__PASSWORD`, `POWERCONTROL__PROXMOX__TOKEN_VALUE` itd.).
- Interfejs webowy **nie ma wbudowanej autoryzacji** – jeśli aplikacja jest dostępna w sieci, zabezpiecz ją (firewall, reverse proxy z auth, VPN) lub nasłuchuj tylko na localhost.
- W produkcji rozważ:
  - HTTPS za reverse proxy (nginx, Caddy),
  - ograniczenie dostępu do portu po IP,
  - wyłączenie lub ograniczenie endpointu `/logs` i `/debug/*`.

---

## Rozwiązywanie problemów

- **Aplikacja startuje, ale przekaźniki nie reagują**  
  Sprawdź, czy jesteś na Raspberry Pi (lub urządzeniu z GPIO) i czy piny w `relay_pins`/`switch_pins` są poprawne. Bez GPIO używane są mocki – przekaźniki w UI mogą się „przełączać”, ale fizycznie nic się nie dzieje.

- **Błąd połączenia z Proxmox**  
  Sprawdź `verify_ssl`, `timeout`, poprawność tokena/hasła i adresu hosta. W logach szukaj komunikatów z `proxmox` / `ProxmoxHelper`.

- **E-maile nie dochodzą**  
  Dla Gmaila włącz „aplikacje mniej bezpieczne” lub użyj hasła aplikacji; sprawdź `server`, `port`, `use_ssl`/`starttls`. Upewnij się, że `enable_email_notifications` i `email.enabled` są włączone. Logi przy wysyłce są w module `emailer`.

- **Fałszywy alarm „awaria zasilania” po restarcie**  
  Aplikacja zapisuje flagę graceful shutdown przy SIGINT/SIGTERM. Jeśli zatrzymujesz ją przez `kill -9` lub awarię zasilania, przy następnym starcie może wysłać powiadomienie o „power loss”. Normalne zatrzymanie (`Ctrl+C` lub `systemctl stop`) zapisuje flagę i nie generuje alarmu.

- **Endpoint `/hosts/list` zwraca offline mimo że host działa**  
  Sprawdź, czy dla hosta z wyłączonym przekaźnikiem nie jest wykonywany ping (aplikacja może traktować „przekaźnik off” jako „host niedostępny bez sprawdzania”). Zweryfikuj konfigurację `computers` (IP, relay).

---

## Licencja

Możesz dodać plik **LICENSE** (np. MIT, GPL) zgodnie z wyborem licencji projektu.
