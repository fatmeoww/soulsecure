# Module 2 — สรุป Flag ทั้งหมด (สำหรับผู้สอน)

**คำเตือน:** ไฟล์นี้มีเฉลย — อย่าแจกให้นักเรียนก่อนจบคอร์ส

รวม **20 flags** จาก 5 labs (15 flag ชุดแรก + 5 flag เพิ่มเติมจากเทคนิค/ความยากที่เพิ่มทีหลัง)
รูปแบบ `flag{md5-hash}` ทั้งหมด (ค่าคงที่ ไม่เปลี่ยนตาม IP หรือ level ที่รัน)

## ⚠️ สถาปัตยกรรมเปลี่ยนแล้ว — อ่านก่อนใช้งาน

Service ส่วนใหญ่ **ไม่มีเลขพอร์ตแล้ว** — เข้าผ่าน `https://<hostname>.soulsecure.lab/`
ทั้งหมด ผ่าน nginx reverse proxy ตัวเดียว (พอร์ต 443) ใช้ cert ที่ออกจาก CA ของ lab เอง
(อายุ 100 ปี ไม่ต้องแก้ทีหลัง) รายละเอียดเต็มดูที่
[Module2-Docker-Ops.md](Module2-Docker-Ops.md)

**Service ที่ยังมีพอร์ตของตัวเอง** (ตั้งใจ — เพราะเป็นบทเรียนเรื่อง "หาแบบไม่มี DNS/ไม่ผ่าน gateway"):
`jenkins-old` (9090), `grafana` (3000), `honeypot` (2121, หลอก), `mail`/SMTP (25),
OSINT Sandbox (9091, เป็น lab utility ไม่ใช่ target)

---

## Lab 1 — Cloud Asset Discovery

| # | จุดที่พบ | เข้าทางไหน | Flag |
|---|---|---|---|
| 1 | `jenkins-old` (shadow IT) | `http://<IP>:9090/` | `flag{cdad904c3f229c8a33f6b9a37b2ec64b}` |
| 2 | `vpn.soulsecure.lab` | `https://vpn.soulsecure.lab/` | `flag{553edeb5b994421a80636e7556fab1b4}` |
| 3 | `backup-eu.soulsecure.lab` | `https://backup-eu.soulsecure.lab/` | `flag{5ff49b3a254b1781f99d3e60f185b706}` |
| 4 ⭐ | Grafana dashboard (พอร์ต 3000) | `http://<IP>:3000/` (เจอผ่าน `/shodan-search`) | `flag{24d7fbca483d726d1ae7ba4c745acd2b}` |

> ⭐ = เพิ่มทีหลัง — พอร์ต 2121 เป็น **honeypot หลอก** (banner vsFTPd 2.3.4)
> **ไม่มี flag** ตั้งใจให้เป็นทางตัน สอนเรื่อง verify ก่อนสรุปผล

## Lab 2 — DNS & Virtual Host Enumeration

| # | จุดที่พบ | เข้าทางไหน | Flag |
|---|---|---|---|
| 1 | `old-www.soulsecure.lab` | `https://old-www.soulsecure.lab/` | `flag{9b1f3a2e6c4d8017f5a3b9e2d4c6f108}` |
| 2 | `internal-tools.soulsecure.lab` (ไม่มี DNS) | vhost brute force: `curl -k --resolve internal-tools.soulsecure.lab:443:<IP> https://internal-tools.soulsecure.lab/` | `flag{3867f231921ee17428ff92e577a8bbc3}` |
| 3 | `legacy-portal.soulsecure.lab` (ไม่มี DNS) | ดู SAN ใน TLS cert แล้ว `curl --resolve` เข้าไป | `flag{e8808bcfa5107695bfee0ee615665001}` |
| 4 ⭐ | `beta.soulsecure.lab` (ไม่มี DNS + ต้องมี header `X-Beta-Access: enabled`) | vhost brute force แล้วอ่าน hint จากหน้า "denied" | `flag{ac12390cdf07e028f08aaf263e19d595}` |

> ⭐ มี CAA record + SRV record (`_autodiscover._tcp`) เพิ่มให้ลองอ่าน และควรลอง
> `dig soulsecure.lab AXFR` ด้วย (คาดหวังผล "Transfer failed")

## Lab 3 — API Reconnaissance

| # | จุดที่พบ | เข้าทางไหน | Flag |
|---|---|---|---|
| 1 | `/api/internal/debug` | `https://api.soulsecure.lab/api/internal/debug` | `flag{3555384be5128ee4c26ffc4992d2c1e1}` |
| 2 | `/api/v2/status` | `https://api.soulsecure.lab/api/v2/status` | `flag{76616423d4eeb78183ccfbf84092b179}` |
| 3 | `/api/v1/orders?id=abc` | `https://api.soulsecure.lab/api/v1/orders?id=abc` | `flag{7c8934797877b254b9db3695a84cbf8b}` |
| 4 ⭐ | `POST /graphql` query `{internalSecret}` | `https://api.soulsecure.lab/graphql` | `flag{b1579ebf26c0e4de304a77b01879d801}` |

> ⭐ `/graphql` ไม่ได้อยู่ใน `openapi.json` — ต้องเดา path
> วิธี introspect: `curl -k https://api.soulsecure.lab/graphql -H "Content-Type: application/json" -d '{"query":"{__schema{queryType{fields{name}}}}"}'`

## Lab 4 — Object Storage Enumeration

| # | จุดที่พบ | เข้าทางไหน | Flag |
|---|---|---|---|
| 1 | `soulsecure-prod-assets/config/backup-2026-07-01.json` | `https://storage.soulsecure.lab/soulsecure-prod-assets/config/backup-2026-07-01.json` | `flag{c3909083d936385564ffe54a86c340b9}` |
| 2 | `soulsecure-backups-eu/db-snapshot-notes.txt` | `https://storage.soulsecure.lab/soulsecure-backups-eu/db-snapshot-notes.txt` | `flag{bb244e7d9025c5600bdc019ad5c726dc}` |
| 3 | `soulsecure-terraform-state/terraform.tfstate` | `https://storage.soulsecure.lab/soulsecure-terraform-state/terraform.tfstate` | `flag{e21e4a4043ae07729741ef42be7dc9af}` |
| 4 ⭐ | GCS-style bucket `soulsecure-gcs-assets` | `https://storage.soulsecure.lab/storage/v1/b/soulsecure-gcs-assets/o/notes%2Fmigration-plan.txt?alt=media` | `flag{b091f26222ff3e2e245ee90a35927202}` |

> ⭐ สังเกต URL รูปแบบ Google Cloud Storage JSON API (`/storage/v1/b/<bucket>/o/...`)
> ต้อง URL-encode `/` ในชื่อ object เป็น `%2F`

## Lab 5 — CDN, Origin & Technology Fingerprinting

| # | จุดที่พบ | เข้าทางไหน | Flag |
|---|---|---|---|
| 1 | `origin-direct.soulsecure.lab` (ไม่มี DNS) | `curl -k --resolve origin-direct.soulsecure.lab:443:<IP> https://origin-direct.soulsecure.lab/` | `flag{8290248cac3247ccf5288ee3f79e39c7}` |
| 2 | `/staging-notes/` | `https://www.soulsecure.lab/staging-notes/` | `flag{d79d7cee7f1e1f4bcdc26fcee00ce18a}` |
| 3 | path ที่ไม่มีอยู่จริงใน `api.soulsecure.lab` | `https://api.soulsecure.lab/<path มั่วๆ>` | `flag{ea97648f7c958c3e5c750862b4ab4519}` |
| 4 ⭐ | `/assets/js/main.js` | `https://www.soulsecure.lab/assets/js/main.js` (hint จาก `security.txt`) | `flag{6f15fea713da8d4e53e704437a6b436a}` |

> ⭐ Bonus (ไม่มี flag แต่ควรฝึก): `search.soulsecure.lab/search` เป็น WAF fingerprint
> exercise — ลอง `?q=hello` (ผ่านปกติ) เทียบกับ `?q=1 union select ...` (โดน block
> พร้อม header `Server: SoulSecure-WAF/2.1`)

---

## รูปแบบดิบ (สำหรับ copy ไปทำ checker script)

```
flag{cdad904c3f229c8a33f6b9a37b2ec64b}
flag{553edeb5b994421a80636e7556fab1b4}
flag{5ff49b3a254b1781f99d3e60f185b706}
flag{9b1f3a2e6c4d8017f5a3b9e2d4c6f108}
flag{3867f231921ee17428ff92e577a8bbc3}
flag{e8808bcfa5107695bfee0ee615665001}
flag{3555384be5128ee4c26ffc4992d2c1e1}
flag{76616423d4eeb78183ccfbf84092b179}
flag{7c8934797877b254b9db3695a84cbf8b}
flag{c3909083d936385564ffe54a86c340b9}
flag{bb244e7d9025c5600bdc019ad5c726dc}
flag{e21e4a4043ae07729741ef42be7dc9af}
flag{8290248cac3247ccf5288ee3f79e39c7}
flag{d79d7cee7f1e1f4bcdc26fcee00ce18a}
flag{ea97648f7c958c3e5c750862b4ab4519}
flag{24d7fbca483d726d1ae7ba4c745acd2b}
flag{ac12390cdf07e028f08aaf263e19d595}
flag{b1579ebf26c0e4de304a77b01879d801}
flag{b091f26222ff3e2e245ee90a35927202}
flag{6f15fea713da8d4e53e704437a6b436a}
```

**หมายเหตุ:** ค่า flag เหล่านี้ **คงที่เสมอ ไม่ว่าจะรันที่ LAB_LEVEL ไหนหรือ IP อะไร** — สิ่งที่เปลี่ยนตาม level คือ "มองเห็น/เข้าถึงได้หรือไม่" เท่านั้น (เช่น flag ของ Lab 4 จะเข้าไม่ถึงเลยถ้ารันที่ LAB_LEVEL ต่ำกว่า 4)
