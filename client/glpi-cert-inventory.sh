#!/bin/bash
set -euo pipefail

OUTPUT="/var/lib/glpi-agent/certificates-inventory.json"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

mkdir -p /var/lib/glpi-agent

CERT_FILES=$(
{
    grep -RihE '^[[:space:]]*SSLCertificateFile[[:space:]]+' /etc/apache2 2>/dev/null \
        | awk '{print $2}' || true

    grep -RihE '^[[:space:]]*ssl_certificate[[:space:]]+' /etc/nginx 2>/dev/null \
        | awk '{gsub(";","",$2); print $2}' || true
} | sort -u
)

python3 - "$OUTPUT" $CERT_FILES <<'PY'
import json
import subprocess
import sys
from datetime import datetime, timezone

output = sys.argv[1]
certs = sys.argv[2:]
softwares = []

def run(*args):
    return subprocess.check_output(args, stderr=subprocess.DEVNULL, text=True).strip()

for cert in certs:
    try:
        run("openssl", "x509", "-in", cert, "-noout")
    except Exception:
        continue

    subject = run("openssl", "x509", "-in", cert, "-noout", "-subject").replace("subject=", "", 1).strip()
    issuer = run("openssl", "x509", "-in", cert, "-noout", "-issuer").replace("issuer=", "", 1).strip()
    serial = run("openssl", "x509", "-in", cert, "-noout", "-serial").split("=", 1)[-1].strip()
    end = run("openssl", "x509", "-in", cert, "-noout", "-enddate").split("=", 1)[-1].strip()
    fp = run("openssl", "x509", "-in", cert, "-noout", "-fingerprint", "-sha256").split("=", 1)[-1].strip()

    try:
        san_raw = run("openssl", "x509", "-in", cert, "-noout", "-ext", "subjectAltName")
        san = " ".join(x.strip() for x in san_raw.splitlines()[1:]).strip()
    except Exception:
        san = ""

    cn = ""
    for part in subject.split(","):
        if "CN =" in part:
            cn = part.split("CN =", 1)[1].strip()
            break
        if part.strip().startswith("CN="):
            cn = part.split("=", 1)[1].strip()
            break

    # Convert OpenSSL date to GLPI-friendly YYYY-MM-DD.
    dt = datetime.strptime(end, "%b %d %H:%M:%S %Y %Z")
    expiration = dt.strftime("%Y-%m-%d")

    # Machine-readable marker. GLPI will initially import this as software;
    # the server-side plugin converts it to a native Certificate.
    metadata = ";".join([
        f"exp={expiration}",
        f"serial={serial}",
        f"fp={fp}",
        f"path={cert}",
        f"san={san.replace(';', ',')}"
    ])

    softwares.append({
        "name": f"GLPI-CERT::{cn or cert}",
        "version": metadata,
        "publisher": issuer
    })

with open(output, "w", encoding="utf-8") as f:
    json.dump({"content": {"softwares": softwares}}, f, ensure_ascii=False)

print(f"Generated {len(softwares)} certificate marker(s) in {output}")
PY

chmod 600 "$OUTPUT"
