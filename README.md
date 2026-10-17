# Forum BSiAW

Prosta aplikacja webowa na laboratorium „Bezpieczeństwo serwerów i aplikacji Web".

- Rejestracja i logowanie użytkownika (sesja Flask)
- Forum: zalogowani użytkownicy dodają wpisy widoczne dla wszystkich
- Baza danych: SQLite lokalnie (później Cloud SQL na GCP)

## Uruchomienie lokalne

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Aplikacja działa pod adresem http://127.0.0.1:5000
