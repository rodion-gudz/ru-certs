#!/usr/bin/env python3
# ru_ct_walker.py — собирает полный актуальный список доменов с сертификатами
# Минцифры (Russian Trusted CA) из российских CT-логов (RFC 6962).
#
# Зависимости:  uv sync  (см. pyproject.toml)
#
# Использование:
#   uv run python ru_ct_walker.py                     # полный проход, идемпотентно (догоняет)
#   uv run python ru_ct_walker.py --limit 512         # быстрый тест на первых записях
#   uv run python ru_ct_walker.py --reset             # сбросить прогресс и начать заново
#   uv run python ru_ct_walker.py --verbose           # лог каждого батча и найденных доменов
#
# Результат:
#   ru_ca_domains.txt / .json        — все SAN-имена, wildcard'ы сохраняются (*.foo.ru):
#                                      подходит для macOS CACertificatesWithConstraints.
#   ru_ca_domains_for_constraints.txt — registrable-домены без wildcard, валидные FQDN
#                                      (для name constraints в cross-signed сертификате).
#   ru_ct_progress.json              — позиция по каждому логу (для догоняющих проходов).
#
# Список логов подгружается из https://browser-resources.s3.yandex.net/ctlog/ctlog.json
# (операторы Yandex/VK/Минцифры). gov-логи (ctlog.digital.gov.ru) подписаны
# «Russian Trusted Sub CA», которого нет в системном хранилище, поэтому TLS-проверка идёт
# по единому бандлу: системные корни (certifi) + certs/ru_full_chain.pem.

import argparse
import base64
import json
import os
import re
import sys
import tempfile
import time

import certifi
from cryptography import x509
import requests
import tldextract

# ── Пути и константы ────────────────────────────────────────────────────────
DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_CA = os.path.join(DIR, "certs", "ru_full_chain.pem")
STATE_FILE = os.path.join(DIR, "ru_ct_progress.json")
OUT_JSON    = os.path.join(DIR, "ru_ca_domains.json")
OUT_TXT     = os.path.join(DIR, "ru_ca_domains.txt")
OUT_BASE    = os.path.join(DIR, "ru_ca_domains_for_constraints.txt")

LOGS_URL = "https://browser-resources.s3.yandex.net/ctlog/ctlog.json"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/151.0.0.0 YaBrowser/26.6.3.910 Yowser/2.5 Safari/537.36")

MAX_REDIRECTS = 5
RETRIES = 6
MAX_ENTRIES = 256                  # get-entries отдаёт до 256 индексов за запрос

INTERESTING_ISSUERS = ("russian trusted", "ministry of digital")

# RFC 6962 entry_type
X509_ENTRY = 0
PRECERT_ENTRY = 1

# ── Логирование ─────────────────────────────────────────────────────────────
def log(msg):
    print(msg, file=sys.stderr, flush=True)

# ── HTTP ────────────────────────────────────────────────────────────────────
class _RateLimited(RuntimeError):
    def __init__(self, wait):
        self.wait = wait
        super().__init__(f"429 — ретрай через {wait}s")

def _retry_after(headers):
    try:
        return min(int(headers.get("Retry-After", "5")), 30)
    except ValueError:
        return 5

def http_get(session, url, params=None, verify=True, tries=RETRIES):
    """GET с ретраями и учётом Retry-After. 400/404 не ретраятся."""
    last = None
    for _ in range(tries):
        try:
            return _http_get_once(session, url, params, verify)
        except LookupError:
            raise
        except Exception as e:
            last = e
            if isinstance(e, _RateLimited):
                time.sleep(e.wait)
    raise RuntimeError(f"GET {url} не удался: {last}")

def _http_get_once(session, url, params, verify):
    """Одиночный GET с ручными редиректами. Любой сбой — исключение."""
    cur = url
    for _ in range(MAX_REDIRECTS + 1):
        r = session.get(cur, params=params, timeout=60, allow_redirects=False, verify=verify)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location")
            if not loc or loc == cur:   # редирект в себя — бывает у LB Яндекса/Mail.ru
                raise RuntimeError("редирект в себя")
            cur = loc
            continue
        if r.status_code == 200 and r.text.strip():
            return r.json()
        if r.status_code == 429:
            raise _RateLimited(_retry_after(r.headers))
        if r.status_code in (400, 404):
            raise LookupError(f"{r.status_code} {r.text[:120]}")
        raise RuntimeError(f"HTTP {r.status_code} для {cur}: {r.text[:120]}")
    raise RuntimeError("слишком много редиректов")

# ── Парсинг CT-записей ──────────────────────────────────────────────────────
def parse_leaf(raw):
    """RFC 6962 merkle_tree_leaf -> (entry_type, payload) или None.

    В российских логах порядок нестандартный: [version:1][leaf_type:1]
    [timestamp:8][entry_type:2][payload...] — timestamp до entry_type.
    """
    if len(raw) < 12 or raw[1] != 0:            # leaf_type != timestamped_entry
        return None
    etype = int.from_bytes(raw[10:12], "big")
    off = 12
    if etype == X509_ENTRY:                     # [len:3] + DER-сертификат
        n = int.from_bytes(raw[off:off + 3], "big")
        return X509_ENTRY, raw[off + 3:off + 3 + n]
    if etype == PRECERT_ENTRY:                  # issuer_key_hash[32] + [len:3] + TBS
        off += 32
        n = int.from_bytes(raw[off:off + 3], "big")
        return PRECERT_ENTRY, raw[off + 3:off + 3 + n]
    return None

# sha256WithRSAEncryption + фиктивная подпись — только чтобы распарсить TBS precert'а
_DUMMY_SIG_ALG = bytes.fromhex("300d06092a864886f70d01010b0500")

def precert_to_cert(tbs):
    """Оборачивает TBS precert'а в полноценный DER (подпись не проверяется)."""
    sig = b"\x03\x82\x01\x01\x00" + b"\x00" * 256
    body = tbs + _DUMMY_SIG_ALG + sig
    return x509.load_der_x509_certificate(b"\x30\x82" + len(body).to_bytes(2, "big") + body)

def extract_domains(leaf):
    """SAN-домены из записи лога; пусто, если сертификат не от Минцифры/Russian Trusted."""
    try:
        parsed = parse_leaf(leaf)
        if parsed is None:
            return []
        etype, payload = parsed
        if etype == PRECERT_ENTRY:
            cert = precert_to_cert(payload)
        else:
            cert = x509.load_der_x509_certificate(payload)
        issuer = cert.issuer.rfc4514_string().lower()
        if not any(m in issuer for m in INTERESTING_ISSUERS):
            return []
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return san.value.get_values_for_type(x509.DNSName)
    except Exception:
        return []

def normalize(name):
    """Чистит SAN-имя, сохраняя wildcard. Возвращает None для мусора.

    Для CACertificatesWithConstraints wildcard обязателен:
    '*.foo.ru' матчит 'foo.ru' и все поддомены, а 'foo.ru' — только точное имя.
    """
    name = name.lower().strip().rstrip(".")
    wild = name.startswith("*.")
    if wild:
        name = name[2:]
    if not name or "*" in name or " " in name or "\n" in name or "/" in name or "\\" in name:
        return None
    return ("*." + name) if wild else name

# Валидный FQDN: две и более меток из [a-z0-9-] (без wildcard, IP и мусора).
# Для name constraints домен без "*." покрывает и сам домен, и все поддомены.
_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
FQDN_RE = re.compile(rf"^(?:{_LABEL}\.)+{_LABEL}$")

def validate_domain(name):
    """Возвращает имя, пригодное для name constraints, или None."""
    name = name.strip().lower().rstrip(".")
    if (not name or len(name) > 253
            or any(len(label) > 63 for label in name.split("."))):
        return None
    return name if FQDN_RE.match(name) else None

def registrable(domain, extract):
    """Корневой (registrable) домен через tldextract или эвристику."""
    if domain.startswith("*."):
        domain = domain[2:]
    try:
        r = extract(domain)
        if r.suffix:
            return f"{r.domain}.{r.suffix}"
    except Exception:
        pass
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) > 2 else domain

# ── Состояние и данные ──────────────────────────────────────────────────────
def load_state():
    """Прогресс: {"pos": {url: int}} — на какой позиции остановились по каждому логу."""
    try:
        with open(STATE_FILE) as f:
            pos = json.load(f).get("pos", {})
    except Exception:
        pos = {}
    return {"pos": pos if isinstance(pos, dict) else {}}

def save_state(state):
    with open(STATE_FILE + ".tmp", "w") as f:
        json.dump(state, f, indent=1)
    os.replace(STATE_FILE + ".tmp", STATE_FILE)

def load_existing_domains():
    """Уже собранные домены из прошлых запусков, чтобы проход их не терял."""
    seen = set()
    for path in (OUT_JSON, OUT_TXT):
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                data = json.load(f) if path.endswith(".json") else f.read().splitlines()
        except Exception:
            continue
        if isinstance(data, list):
            seen.update(d for d in data if isinstance(d, str))
    return seen

def make_session():
    s = requests.Session()
    s.headers["User-Agent"] = UA
    return s

def build_bundle():
    """Единый бандл доверия: системные корни (certifi) + российская цепочка."""
    fd, path = tempfile.mkstemp(prefix="ru-ca-bundle-", suffix=".pem")
    with os.fdopen(fd, "w") as f:
        with open(certifi.where()) as src:
            f.write(src.read())
        with open(DEFAULT_CA) as src:
            f.write("\n" + src.read())
    return path

def load_logs(session, verify):
    """Список usable CT-логов из реестра Яндекса (Yandex/VK/Минцифры)."""
    data = http_get(session, LOGS_URL, verify=verify)
    logs = [lg["url"] for op in data["operators"]
            for lg in op["logs"] if "usable" in lg.get("state", {})]
    if not logs:
        sys.exit(f"ОШИБКА: в {LOGS_URL} нет usable-логов (data: {str(data)[:300]})")
    log(f"Логов в реестре: {len(logs)}")
    return logs

# ── Обход лога ──────────────────────────────────────────────────────────────
def walk_log(session, url, verify, start, limit, domains, state, verbose=False):
    """Идёт по логу от позиции start до конца (или до limit) и наполняет domains."""
    tree = http_get(session, url + "ct/v1/get-sth", verify=verify)["tree_size"]
    end_tree = min(tree, start + limit) if limit else tree
    log(f"[{url}] tree={tree} start={start}" + (f" limit={limit}" if limit else ""))
    pos = start
    while pos < end_tree:
        end = min(pos + MAX_ENTRIES - 1, end_tree - 1)
        try:
            got = http_get(session, url + "ct/v1/get-entries",
                           {"start": pos, "end": end}, verify=verify).get("entries", [])
        except LookupError:
            log(f"[{url}] вышли за границы дерева на {pos}, стоп")
            break
        if not got:
            log(f"[{url}] пустой ответ на {pos}, стоп")
            break
        added = []
        for leaf in got:
            for name in extract_domains(base64.b64decode(leaf["leaf_input"])):
                n = normalize(name)
                if n and n not in domains:
                    domains.add(n)
                    added.append(n)
        if verbose:
            if added:
                shown = ", ".join(added[:20]) + ("..." if len(added) > 20 else "")
                log(f"[{url}] записи {pos}-{end}: получено {len(got)}, "
                    f"новых {len(added)}: {shown}")
            else:
                log(f"[{url}] записи {pos}-{end}: получено {len(got)}, новых нет")
        pos = end + 1
        state["pos"][url] = pos
        save_state(state)
    state["pos"][url] = pos
    save_state(state)

# ── Запись результатов ──────────────────────────────────────────────────────
def write_outputs(domains, extract):
    """Пишет итоговые файлы: все домены (.txt/.json) и registrable для constraints."""
    with open(OUT_JSON, "w") as f:
        json.dump(domains, f, indent=1)
    with open(OUT_TXT, "w") as f:
        f.write("\n".join(domains) + "\n")
    log(f"Записано {len(domains)} доменов -> {OUT_TXT} / {OUT_JSON}")

    base_raw = {registrable(d, extract) for d in domains}
    base = sorted(d for d in (validate_domain(d) for d in base_raw) if d)
    if len(base) != len(base_raw):
        log(f"Отброшено невалидных для constraints: {len(base_raw) - len(base)} "
            "(IP/мусор/не-FQDN)")
    with open(OUT_BASE, "w") as f:
        f.write("\n".join(base) + "\n")
    log(f"Доменов для constraints: {len(base)} -> {OUT_BASE}")

# ── Точка входа ─────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Сборщик доменов Russian Trusted CA из CT-логов")
    ap.add_argument("--limit", type=int, default=0, help="ограничить проход (0 = всё)")
    ap.add_argument("--reset", action="store_true", help="сбросить прогресс и начать заново")
    ap.add_argument("--verbose", action="store_true",
                    help="логировать весь обход (каждый батч записей и найденные домены)")
    opts = ap.parse_args()

    if opts.reset and os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)

    if not os.path.exists(DEFAULT_CA):
        sys.exit(f"ОШИБКА: не найден бандл доверия {DEFAULT_CA}.\n"
                 f"Положите туда полную цепочку (Russian Trusted Root CA + Russian Trusted Sub CA),\n"
                 f"например из koenrh/russian-trusted-root-ca + промежуточный из TLS-цепочек\n"
                 f"mfnso.ru / lesegais.ru.")

    domains = load_existing_domains()
    state = load_state()
    session = make_session()

    if not os.path.exists(OUT_TXT) and not os.path.exists(OUT_JSON):
        state["pos"] = {}
        log("Результатов нет — полный проход с нуля")

    bundle = build_bundle()
    try:
        logs = load_logs(session, bundle)
        for url in logs:
            try:
                walk_log(session, url, bundle, state["pos"].get(url, 0),
                         opts.limit, domains, state, verbose=opts.verbose)
            except Exception as e:
                log(f"[{url}] ошибка: {e} (продолжаю со следующими)")
    finally:
        os.unlink(bundle)

    if domains:
        write_outputs(sorted(domains), tldextract.TLDExtract(suffix_list_urls=()))
    else:
        log("Доменов не найдено — проверь сеть/логи.")

if __name__ == "__main__":
    main()