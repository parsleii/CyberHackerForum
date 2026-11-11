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

## Zmienne środowiskowe

| Zmienna | Opis | Lokalnie |
|---|---|---|
| `SECRET_KEY` | klucz podpisujący sesje i linki z maili | domyślny (tylko DEV) |
| `DATABASE_URL` | adres bazy | SQLite `instance/forum.db` |
| `APP_BASE_URL` | publiczny adres do linków w mailach, np. `https://forum.example.pl` | adres z przeglądarki |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `MAIL_FROM` | wysyłka maili | brak = mail wypisywany w terminalu |
| `GCS_BUCKET` | bucket na załączniki | brak = folder `uploads/` |
| `COOKIE_SECURE` | `1` = ciasteczko sesji tylko po HTTPS | brak |
| `ADMIN_USERNAME` | konto, które dostaje rolę admina przy starcie | – |

