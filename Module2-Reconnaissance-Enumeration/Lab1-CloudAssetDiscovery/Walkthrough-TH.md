# Module 2 — Lab 1: Cloud Asset Discovery — เดินเกมส์แบบละเอียด (ภาษาไทย)

ไฟล์นี้เป็น **transcript จริงของลำดับขั้นตอน** ตั้งแต่ตั้งค่าเครื่อง ไปจนหา subdomain
เจอ แล้วไล่เก็บให้ครบทั้ง 4 flags ของ Lab 1 — ส่วน OSINT Sandbox ใช้ **ผ่านหน้า GUI**
(ไม่ต้องพิมพ์ curl เอง) ส่วนที่เหลือ (DNS, port scan, เข้าดูแต่ละจุด) ยังใช้ command
line ตามปกติ เพราะ Lab 2-5 ไม่มี GUI ให้แล้ว

**Target IP ตอนนี้:** `192.168.174.136` (เปลี่ยนทุกครั้งที่ VM/OVA รีสตาร์ท ให้เช็คกับ
ผู้สอน แล้วแทนที่ทุกจุดด้านล่างด้วย IP จริง)

---

## ขั้นที่ 0: เตรียมเครื่อง (ทำครั้งเดียว)

### 0.1 ตั้ง DNS ให้ชี้ไปที่ target

```bash
sudo bash -c 'echo "nameserver 192.168.174.136" > /etc/resolv.conf'
```

ทดสอบว่าใช้ได้:
```bash
dig soulsecure.lab
```
ถ้าตั้งถูก จะได้ IP กลับมาในส่วน ANSWER SECTION

### 0.2 โหลด + trust CA certificate ของ lab

Service เกือบทั้งหมดอยู่หลัง HTTPS (443) เดียว ใช้ cert ที่ lab ออกเอง ต้องโหลดมาก่อน
ไม่งั้นจะเจอ warning ตลอด (หรือจะใช้ `curl -k` ข้ามไปเลยก็ได้ แต่แนะนำให้ trust ไว้)

```bash
curl -s http://www.soulsecure.lab/ca.crt -o soulsecure-ca.crt
sudo cp soulsecure-ca.crt /usr/local/share/ca-certificates/soulsecure-lab.crt
sudo update-ca-certificates
```

ทดสอบ:
```bash
curl https://www.soulsecure.lab/
```
ถ้าไม่ error เรื่อง cert แปลว่าสำเร็จ

---

## ขั้นที่ 1: หา subdomain ผ่านหน้า GUI ของ OSINT Sandbox

โจทย์เริ่มต้น: ลูกค้าให้ scope มาแค่ `soulsecure.lab`, `www.soulsecure.lab`,
`api.soulsecure.lab` — งานเราคือหาที่เหลือ ใช้ **OSINT Sandbox** (จำลอง
WHOIS/RDAP/ASN/crt.sh/Shodan เพราะ lab นี้ไม่มีอินเทอร์เน็ตจริง) ผ่านหน้าเว็บได้เลย

### 1.1 เปิดหน้า GUI

เปิดเบราว์เซอร์ (Firefox บน Kali ก็ได้) ไปที่:
```
http://192.168.174.136:9091/
```

จะเจอหน้า **"SoulSecure OSINT Sandbox"** มีทั้งหมด 4 การ์ด (การ์ดที่ 5 "Passive DNS
History" จะโผล่เฉพาะตอนเล่นถึง Lab 5 แล้ว ตอนนี้ยังไม่เห็น — ปกติ):

| การ์ด | ใช้ทำอะไร |
|---|---|
| 1. RDAP / WHOIS-style Lookup | หา IP range ที่องค์กรเป็นเจ้าของ |
| 2. ASN Lookup | หา Autonomous System ที่องค์กรประกาศ |
| 3. Certificate Transparency Log | หา subdomain ที่หลุดผ่าน TLS cert ในอดีต |
| 4. Shodan-style Internet Scan | จำลอง internet-wide scan หา asset ที่ไม่ประกาศ |

### 1.2 การ์ดที่ 1 — RDAP / WHOIS Lookup

ช่อง "IP / CIDR" จะมีค่า default ใส่ไว้ให้แล้ว (`192.168.174.0/24`) ไม่ต้องพิมพ์อะไร
เพิ่ม กด **"Look up"**

ผลลัพธ์ที่ได้ (แสดงเป็นตาราง):
- `handle`: SOULSECURE-NET-1
- `name`: SOULSECURE-INC
- `entities`: registrant/abuse contact ของ SoulSecure Inc.
- `remarks`: บอกว่า allocation นี้มีลักษณะแบบ AWS-style direct allocation

ใต้ตารางจะมีบรรทัดสีเขียวโชว์คำสั่งที่เทียบเท่า เช่น:
```
$ curl -s "http://192.168.174.136:9091/rdap?ip=192.168.174.0/24"
```
**เก็บบรรทัดนี้ไว้ — Lab 2-5 ต้องพิมพ์คำสั่งแบบนี้เอง ไม่มีปุ่มให้กดแล้ว**

### 1.3 การ์ดที่ 2 — ASN Lookup

ช่อง "Org name" มีค่า default `soulsecure` กด **"Look up"**

ผลลัพธ์: `asn: AS64512`, `org: SoulSecure Inc.`, `prefixes: 192.168.174.0/24`

### 1.4 การ์ดที่ 3 — Certificate Transparency Log

ช่อง "Domain" มีค่า default `soulsecure.lab` กด **"Search logs"**

ผลลัพธ์เป็นตาราง 3 แถว (3 cert ที่เคยออกให้โดเมนนี้) คอลัมน์ `common_name` และ `san`
สำคัญที่สุด — **นี่คือจุดที่เจอชื่อ subdomain เพิ่มจากที่ลูกค้าให้มา:**

| common_name | san |
|---|---|
| www.soulsecure.lab | www.soulsecure.lab, soulsecure.lab |
| storage.soulsecure.lab | storage.soulsecure.lab, **vpn.soulsecure.lab** |
| backup-eu.soulsecure.lab | backup-eu.soulsecure.lab |

→ เจอเพิ่ม: `storage`, `vpn`, `backup-eu` (ไม่มีอยู่ใน scope email เลย)

### 1.5 การ์ดที่ 4 — Shodan-style Internet Scan

ช่อง "Search term" มีค่า default `soulsecure` กด **"Search"** — **เก็บการ์ดนี้ไว้ใช้
ทีหลังในขั้นที่ 4** (ยังไม่ต้องเก็บ flag ตอนนี้ ให้หา subdomain อื่นก่อน)

ผลลัพธ์จะมี 2 แถว พอร์ต 3000 (Grafana) และพอร์ต 22 (SSH) — จำพอร์ต 3000 ไว้

---

## ขั้นที่ 2: ยืนยัน subdomain ด้วย DNS brute force (command line)

เอาชื่อที่เจอจาก GUI (storage, vpn, backup-eu) + wordlist มาทดสอบว่า resolve จริงไหม:

```bash
for h in www api mail storage backup backup-eu vpn dev staging jenkins jenkins-old admin portal cdn ftp; do
  echo -n "$h : "
  dig +short "$h.soulsecure.lab"
done
```

ผลที่ควรได้ (resolve เป็น IP): `www`, `api`, `mail`, `storage`, `vpn`, `backup-eu`
ส่วน `dev`, `staging`, `jenkins`, `admin`, `portal`, `cdn`, `ftp`, **`jenkins-old`**
จะไม่ resolve เลย (ว่างเปล่า) — `jenkins-old` ตั้งใจไม่มี DNS ต้องหาด้วยวิธีอื่น (ขั้น 4)

**สรุป subdomain ที่เจอตอนนี้:** `www`, `api`, `mail`, `storage`, `vpn`, `backup-eu`

---

## ขั้นที่ 3: Fingerprint แต่ละจุด + เก็บ Flag 1-2

### 3.1 vpn.soulsecure.lab → Flag 1

```bash
curl -s https://vpn.soulsecure.lab/ | grep -o 'flag{[^}]*}'
```
```
flag{553edeb5b994421a80636e7556fab1b4}
```

### 3.2 backup-eu.soulsecure.lab → Flag 2

```bash
curl -s https://backup-eu.soulsecure.lab/ | grep -o 'flag{[^}]*}'
```
```
flag{5ff49b3a254b1781f99d3e60f185b706}
```

### 3.3 mail.soulsecure.lab — ตรวจ banner (ไม่มี flag ตรงนี้ แค่ fingerprint)

```bash
nc mail.soulsecure.lab 25
```
```
220 mail.soulsecure.lab ESMTP Postfix (SoulSecure MailRelay)
```

### 3.4 api.soulsecure.lab — ตรวจ headers/version (fingerprint cloud provider)

```bash
curl -i https://api.soulsecure.lab/version
```
จะเห็น header `X-Amzn-Trace-Id`, `Via: ... CloudFront` และ body มี
`"build_host":"ip-10-0-1-15.ec2.internal"` — สัญญาณชัดว่าเป็น AWS

---

## ขั้นที่ 4: Full port scan หา asset ที่ไม่มี DNS เลย → Flag 3

`jenkins-old` ไม่ resolve ใน DNS เลย (ทดสอบไปแล้วในขั้นที่ 2) ต้องหาด้วยการสแกน
port ตรงๆ บน IP (คำสั่งนี้ไม่มี GUI ให้ ต้องใช้ nmap เอง)

```bash
nmap -p- -sV 192.168.174.136
```

ผลลัพธ์ (ประมาณนี้):
```
22/tcp   open  ssh
25/tcp   open  smtp
53/tcp   open  domain
80/tcp   open  http
443/tcp  open  https
2121/tcp open  ccproxy-ftp    <-- ตรวจดูให้ดี (ดูขั้นที่ 6)
3000/tcp open  ppp             <-- ตรงกับที่เจอใน Shodan-search card (ขั้นที่ 5)
9090/tcp open  zeus-admin      <-- นี่แหละ jenkins-old
9091/tcp open  xmltec-xmlmail  <-- OSINT Sandbox เอง (utility ไม่ใช่ target)
```

สังเกตว่าพอร์ตส่วนใหญ่รวมกันอยู่ที่ 80/443 (ผ่าน gateway เดียว) — พอร์ตที่โดดออกมา
(9090, 3000, 2121) คือของที่ควรตามไปดูต่อ

**เข้าไปดูพอร์ต 9090 ตรงๆ (ไม่มี hostname ต้องใช้ IP:port):**
```bash
curl -s http://192.168.174.136:9090/ | grep -o 'flag{[^}]*}'
```
```
flag{cdad904c3f229c8a33f6b9a37b2ec64b}
```

---

## ขั้นที่ 5: กลับไปที่การ์ด Shodan-search ใน GUI → Flag 4

ย้อนกลับไปหน้า `http://192.168.174.136:9091/` การ์ดที่ 4 ที่กดค้างไว้ตอนขั้น 1.5 —
ผลลัพธ์ที่เห็นจะมีบรรทัดสีเทาใต้ตารางบอกว่า:
```
Connect directly to a port, e.g.  curl http://192.168.174.136:3000/
```

ตรงกับพอร์ต 3000 ที่เจอตอน nmap scan พอดี (ขั้นที่ 4) — ยืนยันแล้วว่าเป็น Grafana จริง
เข้าไปดูตรงๆ ผ่าน browser หรือ curl ก็ได้:

```bash
curl -s http://192.168.174.136:3000/ | grep -o 'flag{[^}]*}'
```
```
flag{24d7fbca483d726d1ae7ba4c745acd2b}
```

---

## ขั้นที่ 6: ระวังจุดหลอก (พอร์ต 2121) — ไม่มี flag ตรงนี้

```bash
echo | nc 192.168.174.136 2121
```
```
220 (vsFTPd 2.3.4)
```

Banner นี้ดูน่าสนใจมาก (เวอร์ชันนี้เคยมี backdoor จริงในปี 2011 — CVE-2011-2523)
แต่ **ในแลปนี้เป็นแค่ banner หลอก ไม่มีอะไรอยู่ข้างหลังจริง ไม่มี flag** — เป็นบท
เรียนเรื่อง "verify ก่อนรายงาน" อย่าเพิ่งตื่นเต้นกับ banner ที่ดูดี ต้องพิสูจน์ก่อน
เสมอ

---

## สรุป: ครบ 4 Flags ของ Lab 1

| # | จุดที่เจอ | วิธีหา | Flag |
|---|---|---|---|
| 1 | `vpn.soulsecure.lab` | GUI (CT-log card) หา ชื่อ → curl เก็บ flag | `flag{553edeb5b994421a80636e7556fab1b4}` |
| 2 | `backup-eu.soulsecure.lab` | GUI (CT-log card) หาชื่อ → curl เก็บ flag | `flag{5ff49b3a254b1781f99d3e60f185b706}` |
| 3 | `jenkins-old` (พอร์ต 9090) | Full port scan (ไม่มี DNS, ไม่มี GUI) | `flag{cdad904c3f229c8a33f6b9a37b2ec64b}` |
| 4 | Grafana (พอร์ต 3000) | GUI (Shodan-search card) | `flag{24d7fbca483d726d1ae7ba4c745acd2b}` |

**เช็คทั้ง 4 flag รวดเดียวผ่าน command line:**
```bash
echo "--- Flag 1 (vpn) ---"; curl -s https://vpn.soulsecure.lab/ | grep -o 'flag{[^}]*}'
echo "--- Flag 2 (backup-eu) ---"; curl -s https://backup-eu.soulsecure.lab/ | grep -o 'flag{[^}]*}'
echo "--- Flag 3 (jenkins-old) ---"; curl -s http://192.168.174.136:9090/ | grep -o 'flag{[^}]*}'
echo "--- Flag 4 (grafana) ---"; curl -s http://192.168.174.136:3000/ | grep -o 'flag{[^}]*}'
```

## หมายเหตุเรื่อง GUI

- GUI มีเฉพาะ **OSINT Sandbox** (พอร์ต 9091) เท่านั้น — ใช้ได้แค่ 4 การ์ด (RDAP, ASN,
  CT-log, Shodan-search) ตามที่ทำในขั้นที่ 1 และ 5
- ทุกอย่างอื่น (DNS query, port scan, เข้าดู vpn/backup-eu/jenkins-old/grafana) **ไม่มี
  GUI** ต้องใช้ command line (`dig`, `curl`, `nmap`, `nc`) เหมือนเดิม
- ทุกปุ่มใน GUI จะโชว์คำสั่ง curl ที่เทียบเท่าให้เสมอ (บรรทัดสีเขียวใต้ปุ่ม) — อ่านไว้
  เพราะ Lab 2 เป็นต้นไปไม่มี GUI ให้อีกแล้ว ต้องพิมพ์เองทั้งหมด

## ต่อไป

Lab 2 (DNS & Virtual Host Enumeration) ต่อยอดจากรายชื่อ subdomain ที่เจอในนี้ทันที —
หลาย hostname ใช้ IP และพอร์ต 443 เดียวกัน แยกกันด้วย TLS SNI/Host header เท่านั้น
และ**ไม่มี GUI ช่วยแล้ว** ต้องใช้ curl/dig/openssl เองทั้งหมด
