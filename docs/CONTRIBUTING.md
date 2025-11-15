# Contributing to PowerControl

Dziękujemy za zainteresowanie wkładem w PowerControl! Ten dokument opisuje proces zgłaszania problemów, sugerowania funkcji i przesyłania pull requestów.

## Kod postu post-acceptance

Przed wkładem upewniaj się:

1. Fork repozytorium na GitHub
2. Utwórz gałąź (`git checkout -b feature/your-feature`)
3. Wprowadź zmiany i Zatwierdź je (`git commit -am 'Add feature'`)
4. Wypchnij do gałęzi (`git push origin feature/your-feature`)
5. Otwórz Pull Request

## Raportowanie problemów (Issues)

### Szablon zgłoszenia błędu

```markdown
## Opis
Krótki opis problemu.

## Kroki do reprodukcji
1. Krok 1
2. Krok 2
3. Krok 3

## Oczekiwane zachowanie
Co powinna robić aplikacja?

## Rzeczywiste zachowanie
Co robi zamiast tego?

## Logi błędu
```
Wklej błąd z logów tutaj
```

## Wersje
- OS: [np. Raspberry Pi OS Bullseye]
- Python: [np. 3.9.2]
- PowerControl: [np. 1.0.0]

## Dodatkowy kontekst
Inne informacje istotne dla problemu.
```

### Szablon sugestii funkcji

```markdown
## Opis
Jaka funkcja byłaby przydatna?

## Motywacja
Dlaczego jest to ważne?

## Proponowana implementacja
Jak powinna działać ta funkcja?

## Dodatkowy kontekst
Benchmarki, wzory użycia itp.
```

## Pull Requests

### Przed wysłaniem PR

- [ ] Kod jest testowany lokalnie
- [ ] Logi są oczyste
- [ ] Bez nieużywanych importów
- [ ] Dodano dokumentację (dla nowych funkcji)
- [ ] Zmian nie spowodują problem dla istniejących użytkowników

### Opis Pull Requesta

```markdown
## Opis zmian
Krótko opisz co zmienia ten PR.

## Typ zmian
- [ ] Naprawa błędu
- [ ] Nowa funkcja
- [ ] Poprawa dokumentacji
- [ ] Refactoring

## Związane Issues
Fixes #123

## Jak testować?
Instrukcje do testowania zmian.

## Checklist
- [ ] Mój kod jest testowany
- [ ] Dokumentacja jest zaktualizowana
- [ ] Brak nowych warningów
- [ ] Testy przechodzą
```

## Style Code

### Python

Stosuj PEP 8:

```python
# Poprawnie
def calculate_status(relay_id: int, enabled: bool) -> dict:
    """Calculate relay status.
    
    Args:
        relay_id: Unique relay identifier
        enabled: Current relay state
        
    Returns:
        Dictionary with status information
    """
    status = {
        'id': relay_id,
        'enabled': enabled,
        'timestamp': datetime.now()
    }
    return status

# Niepoprawnie
def calc_status(relay_id,enabled):
    # Bad style - no type hints, no docstring
    return {'id':relay_id,'enabled':enabled}
```

### Commits

Używaj czystych, opisowych wiadomości commit:

```bash
# Poprawnie
git commit -m "Add relay status caching"
git commit -m "Fix GPIO initialization on startup"
git commit -m "Update documentation for SSL setup"

# Niepoprawnie
git commit -m "fix stuff"
git commit -m "WIP"
git commit -m "asdasd"
```

## Testowanie

### Struktura testów

```
tests/
├── __init__.py
├── test_relay.py
├── test_proxmox.py
└── test_emailer.py
```

### Uruchomienie testów

```bash
python -m pytest tests/
python -m pytest tests/test_relay.py -v
python -m pytest tests/ --cov=app
```

### Przykładowy test

```python
import pytest
from app.relay import RelayController

class TestRelayController:
    @pytest.fixture
    def relay(self):
        return RelayController([17, 27], [], logger=None)
    
    def test_relay_initialization(self, relay):
        assert relay is not None
        assert len(relay.pins) == 2
    
    def test_relay_toggle(self, relay):
        result = relay.toggle(0)
        assert result is True
```

## Licencja

Przesyłając kod, zgadzasz się na licencję projektu (patrz LICENSE).

## Komunikacja

- **Issues**: Dla raportów błędów i sugestii funkcji
- **Pull Requests**: Do dyskusji zmian kodu
- **Discussions**: Dla ogólnych pytań
- **Email**: [maintainer-email] - Kontakt bezpośredni

## Wytyczne społeczności

Wszyscy uczestnicy są zobowiązani do przestrzegania naszego Kodeksu Postępowania:

- Bądź szanowny
- Akceptuj konstruktywną krytykę
- Skoncentruj się na tym, co jest dobre dla społeczności
- Wykaż empatię wobec innych członków

## Wdrażanie

Jedna osoba z zespołu core będzie recenzować PR. Po zatwierdzeniu, zmiany będą scalane i mogą być uwzględnione w następnej wersji.

## Pytania?

Jeśli masz pytania:

1. Sprawdź istniejące issues i PRs
2. Poszukaj w dokumentacji
3. Otwórz dyskusję
4. Skontaktuj się z utrzymującym projektu

Dziękujemy za wkład! 🚀
