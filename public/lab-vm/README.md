# Lab VM — maszyna laboratoryjna Anvil

Część laboratoriów **nie da się wykonać w karcie przeglądarki**: potrzebują jądra,
systemu plików, procesu, kompilatora i możliwości zepsucia czegoś. Takie laby
działają w tej maszynie wirtualnej.

## Co to jest

Minimalistyczny obraz z:

| | |
|---|---|
| `python3`, `ruby`, `rustc`, `cargo` | interpretery i kompilator dla ścieżek Pythona, Rubiego i Rusta |
| `/usr/local/bin/anvil-lab` | usługa labowa z **celową** wadą konfiguracyjną (zadanie `vm-01`) |
| `labcheck` | weryfikacja rozwiązań — działa lokalnie, **zero sieci** |
| `/var/log/anvil-lab.log` | log, w którym zadanie `vm-01` ma znaleźć wyciek |

## Uruchomienie

```bash
# 1. obraz (wymaga qemu-img, qemu-system-x86_64)
bash /build.sh
bash /build.sh --run          # zbuduj i odpal w QEMU (2 GB RAM, SSH na 2222)

# 2. albo tryb hosta — bez QEMU, idealny do nauki i testów
bash /build.sh --host        # kopiuje labcheck i usługę lokalnie
```

## Sprawdzanie rozwiązań

```console
# lab VM:~#
$ labcheck --task vm-01-insecure-flag
FAIL  uruchom usługę: ANVIL_DEBUG=true /usr/local/bin/anvil-lab serve

# lab VM:~#
$ ANVIL_DEBUG=true /usr/local/bin/anvil-lab serve &
$ labcheck --task vm-01-insecure-flag
OK  vm-01: flaga jest w logu, a w nim sekret — dokładnie tego nie chciałeś
```

Zadania Rubiego działają na interpreterze w maszynie:

```console
# lab VM:~#
$ labcheck --task rb-01-enumerable
OK  rb-01-enumerable
```

## Zasady

- **Zero sieci.** Maszyna niczego nie wysyła i niczego nie przyjmuje z sieci.
- **Rozwiązania zostają u Ciebie.** `labcheck` sprawdza lokalnie; platforma nigdy
  nie widzi Twojego kodu z VM.
- **Obrazy są z hasłem SHA-256 w `SHA256SUMS`** — sprawdź przed uruchomieniem
  pobranego obrazu.

## Budowa własnego obrazu

`build.sh` składa katalog `root/` (system plików) i pakuje go do qcow2. Jeśli
chcesz inny zestaw narzędzi, edytuj `root/` w skrypcie albo podmień własny
payload — kontrakt jest prosty: obraz musi mieć `labcheck` w `PATH` i logi
w `/var/log`.

## Co dalej

- Ruby i Rust w przeglądarce (Opal / ruby.wasm) — wtedy VM zostaje tylko dla
  zadań systemowych i exploitów.
- Wspólne pody dla wszystkich uczniów (obraz ~300 MB) oraz zestaw gotowych
  maszyn: metasploitable, DVWA, Juice Shop.