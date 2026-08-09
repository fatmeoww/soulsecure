# Module 2: Reconnaissance & Enumeration — คู่มือเล่นแลป (ภาษาไทย)

**เป้าหมายจำลอง:** SoulSecure Inc. (บริษัท cybersecurity สมมติ), โดเมน `soulsecure.lab`
**Target IP:** ให้ผู้สอนแจ้ง IP ของวันนั้น แล้วแทนที่ `<TARGET_IP>` ด้านล่างด้วย IP จริง
(IP จะเปลี่ยนทุกครั้งที่เปิดเครื่องใหม่/import OVA ใหม่ — เป็นไปตามการออกแบบ)

> **ขอบเขตการทดสอบ:** จำกัดอยู่แค่ `<TARGET_IP>` และโฮสต์ใต้ `soulsecure.lab` เท่านั้น
> ทุกกิจกรรมเป็นการ recon แบบ passive/non-destructive ห้ามทำการโจมตีจริงในโมดูลนี้

ทำตามลำดับ Lab 1 → 5 เพราะ clue จาก lab ก่อนหน้าจะถูกใช้ต่อใน lab ถัดไป

---

## ⚙️ ขั้นตอนที่ 0: ตั้งค่า DNS + trust CA (ทำครั้งเดียว ก่อนเริ่ม Lab 1)

Service เกือบทั้งหมดใน Module นี้อยู่หลัง nginx ตัวเดียว เข้าผ่าน **HTTPS (443) เท่านั้น**
ใช้ cert ที่ออกจาก CA ของ lab เอง (อายุ 100 ปี)

**1) ตั้งค่า nameserver ให้ชี้ไปที่ target**
```bash
sudo bash -c 'echo "nameserver <TARGET_IP>" > /etc/resolv.conf'
```
หลังจากนี้ `*.soulsecure.lab` จะ resolve อัตโนมัติ ไม่ต้องพิมพ์ IP ตรงๆ อีก

**2) โหลด + trust CA certificate ของ lab** (กัน warning TLS ทุกครั้ง)
```bash
curl -s http://www.soulsecure.lab/ca.crt -o soulsecure-ca.crt
# ใช้แบบระบุไฟล์ต่อคำสั่ง:
curl --cacert soulsecure-ca.crt https://www.soulsecure.lab/
# หรือติดตั้งทั้งระบบ (Debian/Kali):
sudo cp soulsecure-ca.crt /usr/local/share/ca-certificates/soulsecure-lab.crt
sudo update-ca-certificates
```
ถ้าไม่อยากยุ่งยาก ใช้ `curl -k` แทนได้ทุกที่ในคู่มือนี้ (ข้าม cert validation)

**Service ที่ยังมีพอร์ตของตัวเอง ไม่ผ่าน gateway** (ตั้งใจ — เป็นบทเรียนเรื่อง
"หาแบบไม่มี DNS/ไม่ผ่าน reverse proxy"): `jenkins-old` (9090), `grafana` (3000),
`honeypot` (2121, หลอก), `mail`/SMTP (25), OSINT Sandbox (9091, utility ไม่ใช่ target)

---

## Lab 1: Cloud Asset Discovery

### สถานการณ์
ลูกค้าส่งอีเมล scope มาให้แค่ 3 โฮสต์ (`soulsecure.lab`, `www.soulsecure.lab`,
`api.soulsecure.lab`) แต่บอกตรงๆ ว่า "cloud footprint ของเราโตแบบไม่มีคนดูแลมานาน
ไม่รู้ว่ามีอะไรอยู่บ้างแล้ว" — งานของเราคือหา asset ที่แท้จริงทั้งหมด

### ขั้นตอน

**1) ทดสอบ DNS**
```bash
dig soulsecure.lab
```

**2) Passive recon ผ่าน OSINT Sandbox** (จำลอง WHOIS/RDAP/ASN/crt.sh/Shodan — ยังอยู่
พอร์ตของตัวเอง เป็น utility ไม่ใช่ target)

💡 **มี GUI ให้ใช้** — เปิด `http://<TARGET_IP>:9091/` ในเบราว์เซอร์ กรอกช่อง กดปุ่ม
ได้เลย ทุกผลลัพธ์โชว์คำสั่ง curl ที่เทียบเท่าให้ดูด้วย เหมาะสำหรับทำความเข้าใจก่อน
ไปใช้ command line เองใน Lab 2-5 (ที่ไม่มี GUI ให้แล้ว)

หรือใช้ command line ตรงๆ:
```bash
curl -s "http://<TARGET_IP>:9091/api"
curl -s "http://<TARGET_IP>:9091/rdap?ip=<TARGET_IP>/24"
curl -s "http://<TARGET_IP>:9091/asn?query=soulsecure"
curl -s "http://<TARGET_IP>:9091/ct-log?domain=soulsecure.lab"
```

**3) DNS brute force**
```bash
for h in www api mail storage backup backup-eu vpn dev staging jenkins jenkins-old admin portal cdn ftp; do
  echo "== $h =="
  dig +short "$h.soulsecure.lab"
done
```

**4) Full port scan บน IP ตรงๆ** (ห้ามข้าม — หัวใจของ lab นี้)
```bash
nmap -p- -sV <TARGET_IP>
```
จะเห็นว่า service ส่วนใหญ่รวมกันอยู่แค่พอร์ต 80/443 (ผ่าน gateway ตัวเดียว) — สมจริง
มาก แต่จะมีบางพอร์ตที่ **ไม่เข้าพวก** เปิดอยู่โดดๆ นั่นแหละคือสิ่งที่ต้องตามหา

**5) Fingerprint แต่ละจุด**
```bash
curl -ik https://www.soulsecure.lab/
curl -ik https://api.soulsecure.lab/version
nc mail.soulsecure.lab 25
```

**6) เก็บ flag** (3 อัน) — ซ่อนใน HTML comment ต้อง `curl` หรือ view-source ไม่ใช่แค่ดูหน้าเว็บ

### 🔥 เพิ่มเติม (ยากขึ้น): Shodan-style search + จุดหลอก

**7) ลองใช้ "internet-wide scan" แทนการ port scan ตรงๆ**
```bash
curl -s "http://<TARGET_IP>:9091/shodan-search?query=soulsecure"
```
ผลลัพธ์จะชี้ไปที่พอร์ตหนึ่งที่มี Grafana dashboard ซ่อนอยู่ — **ไม่มี hostname เลย**
ต้องต่อด้วย IP:port ตรงๆ (`http://<TARGET_IP>:<port>/`) — เก็บ flag ที่นั่น

**8) ระวังจุดหลอก (false positive)**
ระหว่าง full port scan จะเจอพอร์ตหนึ่งที่มี banner `220 (vsFTPd 2.3.4)` — banner นี้
โด่งดังเพราะเวอร์ชันนี้เคยมี backdoor จริง (CVE-2011-2523) **แต่ในแลปนี้เป็นแค่ banner
หลอก ไม่มี flag** — บทเรียนคือ: banner ที่ดูน่าตื่นเต้นเป็นแค่ "เบาะแส" ที่ต้อง
verify ต่อ ไม่ใช่ finding ที่รายงานได้ทันที

---

## Lab 2: DNS & Virtual Host Enumeration

### สถานการณ์
พบแล้วว่าหลาย hostname ใช้ IP **และพอร์ต 443** เดียวกัน — lab นี้เจาะลึกกลไก TLS SNI
+ virtual host ที่ทำให้ IP:port เดียวเสิร์ฟหลายเว็บไซต์ได้

💡 **มี GUI ให้ใช้เหมือนเดิม** — Recon Toolkit ที่ `http://<TARGET_IP>:9091/` การ์ด
5-7 (DNS Lookup, HTTP Request Tool, TLS Certificate Viewer) ครอบคลุมทั้ง lab นี้
รายละเอียดขั้นตอนแบบคลิกทีละจุดดูได้ที่
[Lab 2 Walkthrough](Lab2-DNS-VHost-Enumeration/Walkthrough-TH.md)

### ขั้นตอน

**1) ดึง DNS record ทุกประเภท**
```bash
dig soulsecure.lab TXT
dig soulsecure.lab MX
dig soulsecure.lab CAA
dig _autodiscover._tcp.soulsecure.lab SRV
dig app.soulsecure.lab              # เป็น CNAME ชี้ไปที่ไหน?
```

**2) ลอง zone transfer (AXFR) เสมอ แม้จะรู้ว่าน่าจะ fail**
```bash
dig soulsecure.lab AXFR
```
ปกติจะได้ "Transfer failed" แต่ก็ควรลองทุกครั้ง เพราะถ้าเจอ misconfiguration จะได้
ทั้งโซนมาในทีเดียว

**3) รัน DNS brute force ซ้ำ** (SoulSecure เพิ่ม record ใหม่มาตั้งแต่ Lab 1)

**4) Vhost brute force ผ่าน HTTPS** — ใช้ `curl --resolve` เพื่อ set ทั้ง SNI และ
Host header โดยไม่ต้องพึ่ง DNS จริง (เทคนิคมาตรฐานสำหรับ vhost enum บน HTTPS)
```bash
for h in old-www new-www dev staging test internal internal-tools admin-panel tools legacy legacy-portal portal intranet beta; do
  echo "== $h =="
  curl -sk --resolve "$h.soulsecure.lab:443:<TARGET_IP>" \
    -o /dev/null -w "%{http_code} %{size_download}\n" "https://$h.soulsecure.lab/"
done
```
เทียบ **ขนาด response** ไม่ใช่แค่ status code (server ที่ตั้งไม่ดีมักตอบ 200 ทุกกรณี)

**5) ดึง TLS certificate มาดู SAN (Subject Alternative Name)**
```bash
echo | openssl s_client -connect <TARGET_IP>:443 -servername www.soulsecure.lab 2>/dev/null \
  | openssl x509 -noout -text | grep -A2 "Subject Alternative Name"
```
cert ใบนี้ครอบคลุมหลาย hostname มาก — ส่วนใหญ่คุณรู้จักจาก DNS/vhost brute force
อยู่แล้ว แต่มีชื่อหนึ่งที่ **ไม่เคยโผล่ที่ไหนมาก่อนเลย** ไล่เทียบทีละชื่อ อันไหนไม่ตรง
กับที่รู้มาก่อน = เป้าหมาย ไปเยี่ยมด้วยวิธีเดียวกับข้อ 4

**6) หา vhost ที่มี "ประตู 2 ชั้น"**
ในลิสต์ข้อ 4 มีคำว่า `beta` — จะเจอหน้าที่บอกว่ามีอยู่จริง แต่ต้องส่ง header พิเศษ
ถึงจะเห็นเนื้อหาจริง อ่านข้อความในหน้านั้นให้ดี มันจะบอกชื่อ header ที่ต้องใส่ตรงๆ

**7) อัปเดต asset inventory** — เพิ่มคอลัมน์ "พบด้วยวิธีไหน"

---

## Lab 3: API Reconnaissance

### สถานการณ์
Lab 2 ทิ้ง hint ไว้ว่า "internal API base: /api/internal/" — ถึงเวลาเจาะ
`api.soulsecure.lab` อย่างจริงจัง (**recon เท่านั้น ห้าม exploit ในโมดูลนี้**)

### ขั้นตอน

**1) หา API spec**
```bash
curl -sk https://api.soulsecure.lab/openapi.json | python3 -m json.tool
```

**2) ไล่ทดสอบทุก endpoint ที่ spec บอก** จด method, parameter, response

**3) หา path ที่ดูเหมือน "โน้ตถึงตัวเอง" ไม่ใช่ documentation ปกติ**
ใน field `summary` ของ path นั้นจะมีคำแบบ "remove before...", "do not document..."
— ไปเปิดดู

**4) เดา API version ที่ไม่มีบันทึกไว้**
ทุก path ที่มีใน spec ขึ้นต้นด้วย `/api/v1/` — ลอง `/api/v2/status`

**5) ทำให้ endpoint error แบบตั้งใจ แล้วอ่าน error message ให้ละเอียด**
```bash
curl -sk "https://api.soulsecure.lab/api/v1/orders?id=abc"
```

**6) ทำ API endpoint inventory**

### 🔥 เพิ่มเติม (ยากขึ้น): GraphQL

**7) API สมัยใหม่ไม่ได้มีแต่ REST — ลองหา GraphQL endpoint**
`/openapi.json` ไม่ได้บอกเรื่อง GraphQL เลย ต้องเดา path เอง: ลอง `/graphql`,
`/api/graphql`, `/gql`

**8) ทำ introspection query**
```bash
curl -sk https://api.soulsecure.lab/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{fields{name}}}}"}'
```
ดูรายชื่อ field ที่ตอบกลับมา — field ไหนมีคำอธิบายที่ฟังดูไม่ควรเปิดให้ query ได้เลย?

**9) Query field นั้นตรงๆ**
```bash
curl -sk https://api.soulsecure.lab/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{internalSecret}"}'
```

---

## Lab 4: Object Storage Enumeration

### สถานการณ์
Lab 1 มี HTML comment หลุดชื่อ bucket `soulsecure-prod-assets` พร้อม TODO
"ทำให้ private ก่อน launch" — ซึ่งไม่มีใครทำ

### ขั้นตอน

**1) ยืนยันชื่อ bucket ที่รู้แล้ว**
```bash
curl -sk https://storage.soulsecure.lab/soulsecure-prod-assets/
```

**2) Permutation — เดาชื่อ bucket จากรูปแบบที่พบบ่อย**
```bash
for b in soulsecure-prod-assets soulsecure-dev-assets soulsecure-staging-assets \
         soulsecure-backups-eu soulsecure-backups soulsecure-logs \
         soulsecure-terraform-state soulsecure-tfstate; do
  echo "== $b =="
  curl -sk -o /dev/null -w "%{http_code}\n" "https://storage.soulsecure.lab/$b/"
done
```

**3) อ่าน error code ให้เป็น** — สำคัญมาก
- `NoSuchBucket` → ไม่มี bucket ชื่อนี้อยู่จริง
- `AccessDenied` → **มี bucket นี้อยู่จริง** แค่เข้าไม่ได้ (เป็น finding สำคัญเช่นกัน)
- `200` + ListBucketResult → เปิด public เต็มๆ ลุยได้เลย

**4) โกยของจาก bucket ที่ list ได้**
```bash
curl -sk https://storage.soulsecure.lab/<bucket>/<key>
```

**5) ทำ storage inventory table**

### 🔥 เพิ่มเติม (ยากขึ้น): Cloud provider อื่นที่ไม่ใช่ AWS

**6) SoulSecure ไม่ได้ใช้แค่ AWS** — Google Cloud Storage มี URL รูปแบบเฉพาะตัว
คือ `/storage/v1/b/<bucket>/o` (list) และ `/storage/v1/b/<bucket>/o/<object>?alt=media`
(ดาวน์โหลด) ลองเดาชื่อ bucket แบบเดียวกับ S3 แต่ใช้ path รูปแบบนี้แทน (hostname
เดียวกัน):
```bash
curl -sk "https://storage.soulsecure.lab/storage/v1/b/soulsecure-gcs-assets/o"
```
ถ้า list สำเร็จ ให้ดึงไฟล์แต่ละอันมาอ่าน (ต้อง URL-encode เครื่องหมาย `/`
ในชื่อไฟล์เป็น `%2F` และใส่ `?alt=media` เพื่อขอเนื้อหาไฟล์จริง)

---

## Lab 5: CDN, Origin & Technology Fingerprinting

### สถานการณ์
lab สุดท้าย — หาว่าอะไรอยู่ "หน้า" service จริง (CDN/WAF) แล้วหา origin
ตัวจริงที่อยู่ข้างหลัง ซึ่งมักไม่มีการป้องกันแบบเดียวกับที่ CDN มี

### ขั้นตอน

**1) ดู response headers ของหน้าเว็บหลัก**
```bash
curl -skI https://www.soulsecure.lab/
```
มี header ไหนที่บ่งบอกว่าผ่าน CDN/cache layer มา (`Age`, `X-Cache`)? สังเกตด้วยว่ามี
`Server` header **สองอัน** ไหม (เป็นสัญญาณว่า CDN ไม่ได้ strip header ของ origin ออก)

**2) เช็ค robots.txt และ security.txt**
```bash
curl -sk https://www.soulsecure.lab/robots.txt
curl -sk https://www.soulsecure.lab/.well-known/security.txt
```
path ที่ Disallow ไว้ใน robots.txt ไม่ได้แปลว่าเข้าไม่ได้ — ลองเข้าตรงๆ เลย ส่วน
security.txt มี comment ที่ไม่ควรอยู่ตรงนั้น อ่านดีๆ

**3) อ่าน static JS ไฟล์ที่ไซต์โหลดมาใช้จริง**
```bash
curl -sk https://www.soulsecure.lab/assets/js/main.js
```

**4) หา origin hostname เก่าผ่าน DNS history**
```bash
curl -s "http://<TARGET_IP>:9091/dns-history?domain=www.soulsecure.lab"
```

**5) เข้า origin ตรงๆ โดยข้าม CDN** (รวมเทคนิค vhost brute force จาก Lab 2)
```bash
curl -sk --resolve <hostname ที่เจอ>:443:<TARGET_IP> https://<hostname ที่เจอ>/
```
เทียบ header กับขั้นตอนที่ 1 — หายไปอันไหน? นั่นคือหลักฐานว่านี่คือ origin จริง

**6) ทดสอบว่ามี WAF อยู่หน้าเว็บหรือไม่**
```bash
curl -sk --resolve search.soulsecure.lab:443:<TARGET_IP> \
  "https://search.soulsecure.lab/search?q=hello"
curl -sk --resolve search.soulsecure.lab:443:<TARGET_IP> \
  "https://search.soulsecure.lab/search?q=1%20union%20select%20password%20from%20users"
```
เทียบ response ทั้งสองแบบ — ถ้ามี header หรือหน้า block ที่ต่างออกไปชัดเจน
แปลว่ามี WAF อยู่หน้าเว็บ

**7) ยั่วให้ API เปิดเผย tech stack ผ่าน error handling**
```bash
curl -sk https://api.soulsecure.lab/เส้นทางที่ไม่มีอยู่จริง
```

**8) ทำ final consolidated asset inventory** — รวมทุกอย่างจาก Lab 1-5 เป็นตารางเดียว

---

## เมื่อเล่นจบทั้ง 5 ข้อ

จะได้ asset inventory ที่สมบูรณ์ของ SoulSecure Inc.: DNS, virtual host, API surface,
object storage, และโครงสร้าง CDN/origin ครบ 5 labs, 20 flags (รวมเทคนิคเพิ่มเติม) — พร้อมต่อยอด
Module 3 (Initial Access & Storage Exploitation) ที่จะเริ่มจาก bucket
`soulsecure-prod-assets` ที่เจอใน Lab 4 นี่เอง
