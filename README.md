# Anvil — interactive labs for cybersecurity, Python, Ruby and Rust

Platforma edukacyjna Hartwell Labs: **uczeń pisze kod, kod się wykonuje, checker mówi,
który test nie przeszedł.** Zero kont, zero telemetrii, pierwsze dziesięć labów darmowych.

- **Strona:** https://edu.hartwell-labs.pl (subdomena Cloudflare Worker)
- **Lab:** https://edu.hartwell-labs.pl/lab
- **Manifest zadań (JSON):** https://edu.hartwell-labs.pl/api/manifest
- **Indeks dla AI:** https://edu.hartwell-labs.pl/llms.txt

## Jak to działa

| Wykonawca | Co robi | Gdzie się wykonuje |
|---|---|---|
| `pyodide` | Python w WebAssembly | w przeglądarce ucznia; runtime (12 MB) serwowany z tej samej domeny |
| `quiz` | jedna poprawna odpowiedź, bez kodu | przeglądarka |
| `vm` | wymaga jądra, sieci lub kompilatora | pobrana lab VM, weryfikacja lokalna przez `labcheck` |

Nic nie wychodzi z przeglądarki na serwer: kod i testy uruchamia się u ucznia, wynik
wraca do silnika jako JSON. Postęp leży w `localStorage` i synchronizuje się po
anonimowym ID do `/api/progress`.

## Zadania (13 w tym 3 poza darmowym tierem)

**Python (przeglądarka):** parsowanie logu, weryfikacja SHA-256, trzy warstwy szyfrowania,
detekcja SQL injection. Każde z 3–5 asercji, z komunikatem i wartością.

**Cybersecurity:** nazwij technikę z logu WAF (quiz), wykryj wstrzyknięcie (kod),
prawdziwy lab VM — usługa z celową wadą konfiguracyjną, w której sekret trafia do logu.

**Rust:** przewiduj wyjście programu (ownership, `move`), przeczytaj komunikat
borrow checkera i wybierz poprawkę. Wykonywalny Rust — w lab VM, gdzie kompiluje `cargo`.

**Ruby:** laby na interpreterze w lab VM (`Enumerable`, `gsub` z blokiem, maskowanie
danych w logach).

## Lab VM

```bash
bash lab-vm/build.sh --host   # bez QEMU: konfiguruje labcheck i usługę lokalnie
bash lab-vm/build.sh          # obraz qcow2 (qemu-img, qemu-system-x86_64)
bash lab-vm/build.sh --run    # zbuduj i odpal
```

Zero sieci. `labcheck --task <id>` sprawdza rozwiązanie lokalnie — platforma nigdy
nie widzi kodu pisanego w VM.

## Struktura

```
src/index.js              worker: nagłówki bezpieczeństwa, /api/manifest, /api/progress
public/index.html         strona główna
public/lab/index.html     runner
public/assets/app.js      silnik: Pyodide, checker, postęp, podpowiedzi
public/assets/app.css     styl (spójny z hartwell-labs.pl i wiki)
public/tasks/index.json   wszystkie zadania + rozwiązania referencyjne
public/vendor/pyodide/    runtime Pythona (WASM) — self-hosted, zero CDN
public/lab-vm/            skrypt budowy maszyny, checker, README
check-tasks.py            weryfikacja: każde zadanie musi przechodzić na rozwiązaniu
```

## Rozwój

```bash
python3 check-tasks.py                 # sprawdź, że zadania się rozwiązują
python3 -m http.server 8080 -d public  # lokalne podglądanie

CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ACCOUNT_ID=... npx wrangler deploy
```

## Podpięcie subdomeny

`wrangler.toml` definiuje trasę `edu.hartwell-labs.pl`. Token CF używany do wdrożeń
nie ma zakresu *Workers Domains*, więc samo `custom_domain = true` się pomija — subdomenę
trzeba raz podpiąć w panelu: **Workers & Pages → hartwell-edu → Settings → Domains &
Routes → Add → `edu.hartwell-labs.pl`**. Po tym `npx wrangler deploy` ogarnia resztę.

## Dalszy plan

1. Ruby w przeglądarce (Opal ~1 MB albo `ruby.wasm`) — wtedy VM zostaje tylko dla
   zadań systemowych i exploitów.
2. Wspólne obrazy VM dla uczniów (~300 MB) + zestaw gotowych maszyn.
3. Serwerowy runner dla labów, które wymagają sieci, z kontrolą czasu i limitów.
4. Pisywalne ścieżki na zamówienie (poza darmowym tierem, wyceniane indywidualnie).