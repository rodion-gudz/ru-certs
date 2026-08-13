#!/usr/bin/env python3
"""Генерация cross-signed НУЦ с name constraints.

Использование:
  python3 gen_certs.py [список_доменов] [выходная_папка] [--force]

Создаёт:  myca.{key,crt} (якорь, ключ один раз), cross-signed-nuc.{pem,cer},
          constraints.cnf, permitted_domains.txt.
"""
import datetime
import os
import re
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
DOMAINS = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") \
    else os.path.join(BASE, "ru_ca_domains_for_constraints.txt")
OUT = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("-") \
    else os.path.join(BASE, "CA")
NUC = os.path.join(BASE, "certs", "root-ca_rsa-2022.pem")
FORCE = "--force" in sys.argv

_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
FQDN_RE = re.compile(rf"^(?:{_LABEL}\.)+{_LABEL}$")


def sh(*cmd, capture=True):
    r = subprocess.run([str(x) for x in cmd], capture_output=True, text=True)
    if r.returncode:
        print("ОШИБКА:", *cmd, "\n", r.stderr[-1500:], file=sys.stderr)
        sys.exit(1)
    return r.stdout.strip() if capture else r.stdout


def main():
    bad, clean = [], []
    with open(DOMAINS, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            s = line.strip().lower().rstrip(".")
            if not s or s.startswith(("#", ";", "//")):
                continue
            (clean if FQDN_RE.match(s) else bad).append(s)
    clean = sorted(set(clean))
    for line in bad[:10]:
        print(f"! пропущен: {line}")
    print(f"доменов для constraints: {len(clean)}")
    if bad and not FORCE:
        print("ОСТАНОВ: есть невалидные домены (исправь список или добавь --force)")
        sys.exit(1)

    NUC_CSR = os.path.join(OUT, "nuc.csr")
    NUC_PUB = os.path.join(OUT, "nuc_pub.pem")
    KEY, CRT = os.path.join(OUT, "myca.key"), os.path.join(OUT, "myca.crt")
    os.makedirs(OUT, exist_ok=True)
    open(os.path.join(OUT, "permitted_domains.txt"), "w").write("\n".join(clean) + "\n")

    if not os.path.exists(KEY):
        print("создаю корневой CA (RSA 4096)")
        sh("openssl", "genrsa", "-out", KEY, "4096")
        os.chmod(KEY, 0o600)
        sh("openssl", "req", "-x509", "-new", "-key", KEY, "-out", CRT, "-days", 3650,
           "-subj", "/CN=RU Constrained Certs Root CA",
           "-addext", "basicConstraints=critical,CA:TRUE",
           "-addext", "keyUsage=critical,keyCertSign,cRLSign")

    end = datetime.datetime.strptime(
        sh("openssl", "x509", "-in", NUC, "-noout", "-enddate").split("=", 1)[1].strip(),
        "%b %d %H:%M:%S %Y %Z")
    days = max((end - datetime.datetime.now()).days - 31, 30)

    nclist = ",".join(f"permitted;DNS:{d}" for d in clean)
    open(os.path.join(OUT, "constraints.cnf"), "w").write(
        "basicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        f"nameConstraints=critical,{nclist}\n")

    pub = sh("openssl", "x509", "-in", NUC, "-pubkey", "-noout")
    open(NUC_PUB, "w").write(pub + "\n")
    sh("openssl", "x509", "-in", NUC, "-x509toreq", "-signkey", KEY, "-out", NUC_CSR)
    CROSS = os.path.join(OUT, "cross-signed-nuc.pem")
    sh("openssl", "x509", "-req", "-in", NUC_CSR,
       "-CA", CRT, "-CAkey", KEY, "-set_serial", hex(int(datetime.datetime.now().timestamp())),
       "-days", days, "-force_pubkey", NUC_PUB, "-extfile", os.path.join(OUT, "constraints.cnf"),
       "-out", CROSS)
    sh("openssl", "x509", "-in", CROSS, "-outform", "der", "-out", os.path.join(OUT, "cross-signed-nuc.cer"))
    sh("openssl", "x509", "-in", CRT, "-outform", "der", "-out", os.path.join(OUT, "myca.cer"))

    sh("openssl", "verify", "-CAfile", CRT, CROSS)
    print(f"OK: {len(clean)} доменов, срок {days} дн. (до {end.strftime('%Y-%m-%d')})")
    print(f"""
Файлы: {OUT}/myca.key (СЕКРЕТ), myca.crt|myca.cer, cross-signed-nuc.pem|.cer

macOS (запросит пароль):
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {CRT}
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {OUT}/cross-signed-nuc.cer

Обновление списка: правь список -> python3 gen_certs.py -> замени cross-signed-nuc.cer:
  sudo security delete-certificate -c "Russian Trusted Root CA" /Library/Keychains/System.keychain
  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {OUT}/cross-signed-nuc.cer
""")


if __name__ == "__main__":
    main()