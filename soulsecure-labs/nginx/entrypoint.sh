#!/bin/sh
set -e
LAB_MODULE="${LAB_MODULE:-2}"
LAB_LEVEL="${LAB_LEVEL:-5}"

# Module 3+ continues the same tenant -- Module 2's content never disappears
# once you move past it (see Module3-Overview.md "does not reset"). LAB_LEVEL
# means "level within whichever module is currently active", so once
# LAB_MODULE > 2, Module 2 content must render as if it were fully unlocked
# (level 5), regardless of what LAB_LEVEL is set to for the current module.
if [ "$LAB_MODULE" -gt 2 ]; then
    M2_LEVEL=5
else
    M2_LEVEL="$LAB_LEVEL"
fi

# Same pattern for Module 3's effective level.
if [ "$LAB_MODULE" -gt 3 ]; then
    M3_LEVEL=5
elif [ "$LAB_MODULE" -eq 3 ]; then
    M3_LEVEL="$LAB_LEVEL"
else
    M3_LEVEL=0
fi

# Same pattern for Module 4's effective level.
if [ "$LAB_MODULE" -gt 4 ]; then
    M4_LEVEL=5
elif [ "$LAB_MODULE" -eq 4 ]; then
    M4_LEVEL="$LAB_LEVEL"
else
    M4_LEVEL=0
fi

if [ "$LAB_MODULE" -gt 5 ]; then
    M5_LEVEL=5
elif [ "$LAB_MODULE" -eq 5 ]; then
    M5_LEVEL="$LAB_LEVEL"
else
    M5_LEVEL=0
fi

if [ "$LAB_MODULE" -gt 6 ]; then
    M6_LEVEL=5
elif [ "$LAB_MODULE" -eq 6 ]; then
    M6_LEVEL="$LAB_LEVEL"
else
    M6_LEVEL=0
fi

SRC=/opt/nginx-src
LIVE=/opt/soulsecure-lab
TLS=$LIVE/tls

mkdir -p "$LIVE/www" "$LIVE/backup" "$TLS"
rm -rf /etc/nginx/conf.d
mkdir -p /etc/nginx/conf.d /etc/nginx/snippets

# --- content: always present (Lab 1) ---
cp -r "$SRC/content/www/." "$LIVE/www/" 2>/dev/null || true
cp -r "$SRC/content/backup/." "$LIVE/backup/"

# By default no extra CDN-style headers (Lab 5 adds them below).
: > /etc/nginx/snippets/www-extra-headers.conf
# By default no Basic Auth on the backup portal (M3 Lab 4 adds it below).
: > /etc/nginx/snippets/backup-extra.conf

# Lab 1 www content should NOT include Lab 5's robots.txt/staging-notes/etc
# unless LAB_LEVEL >= 5 -- strip them back out if they got copied above.
if [ "$M2_LEVEL" -lt 5 ]; then
    rm -f "$LIVE/www/robots.txt"
    rm -rf "$LIVE/www/staging-notes" "$LIVE/www/.well-known" "$LIVE/www/assets"
fi

# --- Lab 2: extra vhosts ---
if [ "$M2_LEVEL" -ge 2 ]; then
    mkdir -p "$LIVE/old-www" "$LIVE/internal-tools" "$LIVE/legacy-portal" "$LIVE/beta" "$LIVE/beta-denied"
    cp -r "$SRC/content/old-www/." "$LIVE/old-www/"
    cp -r "$SRC/content/internal-tools/." "$LIVE/internal-tools/"
    cp -r "$SRC/content/legacy-portal/." "$LIVE/legacy-portal/"
    cp -r "$SRC/content/beta/." "$LIVE/beta/"
    cp -r "$SRC/content/beta-denied/." "$LIVE/beta-denied/"
fi

# --- Lab 5: origin bypass, robots.txt/staging-notes, CDN-shaped headers ---
if [ "$M2_LEVEL" -ge 5 ]; then
    mkdir -p "$LIVE/origin-direct"
    cp -r "$SRC/content/origin-direct/." "$LIVE/origin-direct/"
    cp "$SRC/content/www/robots.txt" "$LIVE/www/robots.txt"
    mkdir -p "$LIVE/www/staging-notes"
    cp -r "$SRC/content/www/staging-notes/." "$LIVE/www/staging-notes/"
    cp "$SRC/conf/lab5-extra-headers.conf" /etc/nginx/snippets/www-extra-headers.conf
fi

# --- Module 3 Lab 4: backup portal Basic Auth + downloadable archives ---
if [ "$M3_LEVEL" -ge 4 ]; then
    mkdir -p "$LIVE/backup/files"
    cp -r "$SRC/content/backup-files/." "$LIVE/backup/files/"
    HTPASSWD="$LIVE/htpasswd-backup"
    printf 'ops-eu:%s\n' "$(openssl passwd -apr1 'Backup2025!')" > "$HTPASSWD"
    cat > /etc/nginx/snippets/backup-extra.conf <<EOF
location /files/ {
    auth_basic "SoulSecure Backup Portal (EU)";
    auth_basic_user_file $HTPASSWD;
    autoindex on;
}
EOF
    # Module 5 Lab 4: the one dynamic route on backup-eu -- everything else
    # on this vhost stays static content served directly by nginx.
    if [ "$M5_LEVEL" -ge 4 ]; then
        cat >> /etc/nginx/snippets/backup-extra.conf <<EOF
location /admin/export-all {
    set \$upstream_backup_admin backup-admin:8700;
    proxy_pass http://\$upstream_backup_admin;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Access-Key-Id \$http_x_access_key_id;
    proxy_set_header X-Secret-Access-Key \$http_x_secret_access_key;
}
EOF
    fi
fi

# --- Module 6: static training-material downloads (Labs 3/4) ---
if [ "$M6_LEVEL" -ge 1 ]; then
    mkdir -p "$LIVE/module6-downloads"
    cp -r "$SRC/content/module6-downloads/." "$LIVE/module6-downloads/"
fi

# ---------------------------------------------------------------------------
# TLS: one CA-signed server cert for the whole deployment, 100-year validity
# on both the CA and the server cert -- generated fresh on every container
# start (cheap, ~1s) so it always matches whatever LAB_LEVEL is active. The
# SAN list is built incrementally, same gating logic as everything else, so
# a cert pulled at LAB_LEVEL=1 doesn't leak names that only exist at higher
# levels.
# ---------------------------------------------------------------------------
SAN="DNS:www.soulsecure.lab,DNS:soulsecure.lab,DNS:api.soulsecure.lab,DNS:storage.soulsecure.lab,DNS:vpn.soulsecure.lab,DNS:backup-eu.soulsecure.lab"
if [ "$M2_LEVEL" -ge 2 ]; then
    SAN="$SAN,DNS:old-www.soulsecure.lab,DNS:app.soulsecure.lab,DNS:internal-tools.soulsecure.lab,DNS:beta.soulsecure.lab,DNS:legacy-portal.soulsecure.lab"
fi
if [ "$M2_LEVEL" -ge 5 ]; then
    SAN="$SAN,DNS:origin-direct.soulsecure.lab,DNS:search.soulsecure.lab"
fi
if [ "$M4_LEVEL" -ge 1 ]; then
    SAN="$SAN,DNS:iam.soulsecure.lab"
fi
if [ "$M5_LEVEL" -ge 2 ]; then
    SAN="$SAN,DNS:bastion.soulsecure.lab"
fi
if [ "$M6_LEVEL" -ge 1 ]; then
    SAN="$SAN,DNS:module6.soulsecure.lab"
fi

if [ ! -f "$TLS/ca.crt" ] || [ ! -f "$TLS/soulsecure.crt" ]; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 36500 \
        -keyout "$TLS/ca.key" -out "$TLS/ca.crt" \
        -subj "/C=SG/O=SoulSecure Inc./CN=SoulSecure Lab Root CA" 2>/dev/null

    openssl req -nodes -newkey rsa:2048 \
        -keyout "$TLS/soulsecure.key" -out "$TLS/soulsecure.csr" \
        -subj "/C=SG/O=SoulSecure Inc./CN=www.soulsecure.lab" 2>/dev/null

    printf "subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" "$SAN" > "$TLS/server-ext.cnf"

    openssl x509 -req -in "$TLS/soulsecure.csr" \
        -CA "$TLS/ca.crt" -CAkey "$TLS/ca.key" -CAcreateserial \
        -out "$TLS/soulsecure.crt" -days 36500 \
        -extfile "$TLS/server-ext.cnf" 2>/dev/null

    chmod 644 "$TLS/ca.crt" "$TLS/soulsecure.crt"
    chmod 600 "$TLS/ca.key" "$TLS/soulsecure.key"
fi

cat > /etc/nginx/conf.d/00-ssl.conf <<EOF
ssl_certificate     $TLS/soulsecure.crt;
ssl_certificate_key $TLS/soulsecure.key;
ssl_protocols TLSv1.2 TLSv1.3;

# Port 80: only the CA cert is servable in the clear (so clients can fetch
# and trust it before ever speaking TLS to this host); everything else
# redirects to https.
server {
    listen 80 default_server;
    server_name _;

    location = /ca.crt {
        alias $TLS/ca.crt;
        default_type application/x-x509-ca-cert;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}
EOF

# --- always-on 443 vhosts (Lab 1 core) ---
cp "$SRC/conf/lab1.conf" /etc/nginx/conf.d/10-lab1.conf

if [ "$M2_LEVEL" -ge 2 ]; then
    cp "$SRC/conf/lab2.conf" /etc/nginx/conf.d/20-lab2.conf
fi

if [ "$M2_LEVEL" -ge 5 ]; then
    cp "$SRC/conf/lab5.conf" /etc/nginx/conf.d/50-lab5.conf
fi

if [ "$M4_LEVEL" -ge 1 ]; then
    cp "$SRC/conf/lab-m4.conf" /etc/nginx/conf.d/40-module4.conf
fi

if [ "$M5_LEVEL" -ge 2 ]; then
    cp "$SRC/conf/lab-m5.conf" /etc/nginx/conf.d/50-module5.conf
fi

if [ "$M6_LEVEL" -ge 1 ]; then
    cp "$SRC/conf/lab-m6.conf" /etc/nginx/conf.d/60-module6.conf
fi

echo "soulsecure-nginx: LAB_MODULE=$LAB_MODULE LAB_LEVEL=$LAB_LEVEL (effective M2 level=$M2_LEVEL, M3 level=$M3_LEVEL, M4 level=$M4_LEVEL, M5 level=$M5_LEVEL, M6 level=$M6_LEVEL)"
echo "soulsecure-nginx: cert SAN = $SAN"
nginx -t

exec nginx -g 'daemon off;'
