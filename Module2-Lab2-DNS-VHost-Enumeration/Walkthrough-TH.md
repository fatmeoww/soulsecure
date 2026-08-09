# Module 2 — Lab 2: DNS & Virtual Host Enumeration — เดินเกมส์แบบละเอียด (ภาษาไทย)

ไฟล์นี้เป็น **transcript จริงของลำดับขั้นตอน** ไล่เก็บให้ครบทั้ง 4 flags ของ Lab 2 —
ใช้ **Recon Toolkit GUI** (พอร์ต 9091 การ์ด 5-7) เป็นหลัก สลับกับ command line
ในจุดที่ GUI ทำไม่ได้ (เช่น zone transfer)

**Target IP ตอนนี้:** `192.168.174.136` (เช็คกับผู้สอนทุกครั้งที่เปิดเครื่องใหม่)

**ก่อนเริ่ม:** ต้องตั้ง DNS + trust CA ตามขั้นที่ 0 ของ Lab 1 ไว้แล้ว (ดูใน
[Lab 1 Walkthrough](../Module2-Lab1-CloudAssetDiscovery/Walkthrough-TH.md#ขั้นที่-0-เตรียมเครื่อง-ทำครั้งเดียว))
ถ้ายังไม่ได้ทำ ให้ย้อนไปทำก่อน

---

## ขั้นที่ 1: ดึง DNS record ทุกประเภทผ่าน GUI

เปิด `http://192.168.174.136:9091/` เลื่อนลงมาที่หัวข้อ **"Recon toolkit"** →
การ์ดที่ 5 **"DNS Lookup"**

ช่อง Domain ใส่ `soulsecure.lab` แล้วเปลี่ยน dropdown "Type" ทีละอัน กด **Query**:

| Type ที่เลือก | ผลลัพธ์ที่ควรเห็น |
|---|---|
| A | `soulsecure.lab. 300 IN A 192.168.174.136` |
| TXT | 2 บรรทัด: `v=spf1 include:_spf.soulsecure.lab ~all` และ `soulsecure-site-verification=...` |
| MX | `10 mail.soulsecure.lab.` |
| CAA | `0 issue "letsencrypt.org"` |
| CNAME | (ว่าง สำหรับ apex — ลองเปลี่ยน domain เป็น `app.soulsecure.lab` แทนดู) |

**ลอง CNAME กับ `app.soulsecure.lab`:** เปลี่ยนช่อง Domain เป็น `app.soulsecure.lab`
เลือก Type = CNAME กด Query → เห็น `app.soulsecure.lab. 300 IN CNAME
www.soulsecure.lab.`

**ลอง SRV:** เปลี่ยน Domain เป็น `_autodiscover._tcp.soulsecure.lab` เลือก Type = SRV
→ เห็น `0 5 443 www.soulsecure.lab.`

ทุกครั้งที่กด Query จะมีบรรทัดสีเขียวโชว์คำสั่ง `dig` ที่เทียบเท่าให้ดูด้วย

## ขั้นที่ 2: ลอง Zone Transfer (AXFR) — ไม่มี GUI ต้องใช้ command line

```bash
dig soulsecure.lab AXFR
```
ผลลัพธ์ที่ควรได้: `; Transfer failed.` — เป็นผลลัพธ์ปกติ (DNS server สมัยใหม่ปิด AXFR
กันหมด) แต่ **ต้องลองทุกครั้ง** เพราะถ้าเจอ misconfiguration จะได้ทั้งโซนมาในทีเดียว

## ขั้นที่ 3: DNS brute force หา subdomain ที่ยังไม่รู้ → Flag 1

กลับไปที่การ์ด **"DNS Lookup"** ใน GUI ลองเปลี่ยน Domain ไล่ทีละชื่อ (Type = A):
`old-www`, `new-www`, `dev`, `staging`, `test`, `internal`, `internal-tools`,
`admin-panel`, `tools`, `legacy`, `legacy-portal`, `portal`, `intranet`, `beta`

(หรือจะ loop ผ่าน command line เร็วกว่า:)
```bash
for h in old-www new-www dev staging test internal internal-tools admin-panel tools legacy legacy-portal portal intranet beta; do
  echo -n "$h : "; dig +short "$h.soulsecure.lab"
done
```

จะเจอแค่ `old-www.soulsecure.lab` ที่ resolve ได้จริง (ตัวอื่นว่างเปล่าหมด) เข้าไปดู:
```bash
curl -sk https://old-www.soulsecure.lab/ | grep -o 'flag{[^}]*}'
```
```
flag{9b1f3a2e6c4d8017f5a3b9e2d4c6f108}
```

## ขั้นที่ 4: Vhost brute force ผ่าน GUI (ไม่มี DNS) → Flag 2

ชื่อที่เหลือจากขั้นที่ 3 (ที่ DNS ไม่ resolve) ยังต้องลองต่อ เพราะ vhost ไม่จำเป็นต้องมี
DNS record — ใช้การ์ดที่ 6 **"HTTP(S) Request Tool"**:

1. ช่อง **Hostname** ใส่ `internal-tools.soulsecure.lab`
2. **Method** = GET, **Path** = `/`
3. กด **Send Request**

ผลลัพธ์: `HTTP 200` พร้อมเนื้อหาหน้า Internal Tools — เจอ flag ใน body:
```
<!-- flag: flag{3867f231921ee17428ff92e577a8bbc3} -->
```

ลองไล่ hostname อื่นในลิสต์เดียวกันด้วยวิธีเดียวกัน (`beta`, `legacy-portal` จะเจอใน
ขั้นถัดไป) — สังเกตว่าใต้ปุ่ม Send Request จะโชว์คำสั่ง `curl --resolve` ที่เทียบเท่า
ให้ด้วย เก็บไว้ใช้เอง เพราะ Lab 3 เป็นต้นไปยังต้องใช้เทคนิคนี้อยู่

## ขั้นที่ 5: ดู TLS Certificate SAN list ผ่าน GUI → Flag 3

การ์ดที่ 7 **"TLS Certificate Viewer"**:

1. ช่อง **Hostname** ใส่ `www.soulsecure.lab` (ใช้ชื่อไหนก็ได้ที่รู้จักอยู่แล้ว
   เพราะทุก vhost ใช้ cert ใบเดียวกัน)
2. กด **Get Certificate**

ผลลัพธ์แสดง **SAN list** ทั้งหมด — ไล่เทียบทีละชื่อกับที่รู้จักมาแล้ว
(www, api, storage, vpn, backup-eu, old-www, app, internal-tools, beta) จะเจอชื่อ
หนึ่งที่ไม่เคยเจอที่ไหนมาก่อนเลย: **`legacy-portal.soulsecure.lab`**

เอาไปทดสอบต่อในการ์ด **"HTTP(S) Request Tool"** (การ์ดที่ 6):
- Hostname: `legacy-portal.soulsecure.lab`
- Path: `/`
- Send Request

```
<!-- flag: flag{e8808bcfa5107695bfee0ee615665001} -->
```

## ขั้นที่ 6: Vhost ที่มี "ประตู 2 ชั้น" → Flag 4 (harder mode)

จากขั้นที่ 3-4 ชื่อ `beta` ก็ไม่ resolve DNS เหมือนกัน ลองทดสอบด้วย HTTP Request Tool:

**ครั้งที่ 1 — ไม่ใส่ header อะไรเพิ่ม:**
- Hostname: `beta.soulsecure.lab`
- Path: `/`
- Headers: (เว้นว่าง)
- Send Request

ผลลัพธ์: `HTTP 200` แต่หน้าเป็น "Beta Program" บอกว่ายังไม่ปลดล็อก พร้อมบอกใบ้ว่า
ต้องส่ง header ชื่อ `X-Beta-Access: enabled`

**ครั้งที่ 2 — ใส่ header ตามที่บอก:**
- Hostname: `beta.soulsecure.lab`
- Path: `/`
- **Headers:** พิมพ์ `X-Beta-Access: enabled`
- Send Request

```
<!-- flag: flag{ac12390cdf07e028f08aaf263e19d595} -->
```

---

## สรุป: ครบ 4 Flags ของ Lab 2

| # | จุดที่เจอ | วิธีหา | Flag |
|---|---|---|---|
| 1 | `old-www.soulsecure.lab` | DNS Lookup (GUI) brute force | `flag{9b1f3a2e6c4d8017f5a3b9e2d4c6f108}` |
| 2 | `internal-tools.soulsecure.lab` (ไม่มี DNS) | HTTP Request Tool (GUI) brute force | `flag{3867f231921ee17428ff92e577a8bbc3}` |
| 3 | `legacy-portal.soulsecure.lab` (ไม่มี DNS) | TLS Certificate Viewer (GUI) → SAN list | `flag{e8808bcfa5107695bfee0ee615665001}` |
| 4 ⭐ | `beta.soulsecure.lab` (ไม่มี DNS + header) | HTTP Request Tool (GUI) + header `X-Beta-Access` | `flag{ac12390cdf07e028f08aaf263e19d595}` |

**เช็คทั้ง 4 flag รวดเดียวผ่าน command line:**
```bash
echo "--- Flag 1 (old-www) ---"; curl -sk https://old-www.soulsecure.lab/ | grep -o 'flag{[^}]*}'
echo "--- Flag 2 (internal-tools) ---"; curl -sk --resolve internal-tools.soulsecure.lab:443:192.168.174.136 https://internal-tools.soulsecure.lab/ | grep -o 'flag{[^}]*}'
echo "--- Flag 3 (legacy-portal) ---"; curl -sk --resolve legacy-portal.soulsecure.lab:443:192.168.174.136 https://legacy-portal.soulsecure.lab/ | grep -o 'flag{[^}]*}'
echo "--- Flag 4 (beta) ---"; curl -sk --resolve beta.soulsecure.lab:443:192.168.174.136 https://beta.soulsecure.lab/ -H "X-Beta-Access: enabled" | grep -o 'flag{[^}]*}'
```

## หมายเหตุเรื่อง GUI ใน Lab 2

- ใช้ได้ 3 การ์ดจาก Recon Toolkit: **DNS Lookup** (ขั้น 1, 3), **HTTP(S) Request Tool**
  (ขั้น 4, 5, 6), **TLS Certificate Viewer** (ขั้น 5)
- **Zone transfer (AXFR)** ไม่มี GUI ให้ ต้องใช้ `dig ... AXFR` เอง (เป็นเทคนิคที่ควร
  ลองด้วยมือเสมอ ไม่ใช่แค่กดปุ่ม)
- ทุกผลลัพธ์ใน GUI โชว์คำสั่ง CLI ที่เทียบเท่าเสมอ — Lab 3 เป็นต้นไปยังใช้ GUI นี้ได้
  อยู่ (การ์ด 5-7 ใช้ได้ทุก lab) แต่เนื้อหา/เทคนิคเฉพาะของแต่ละ lab จะซับซ้อนขึ้น

## ต่อไป

Lab 3 (API Reconnaissance) เจาะลึก `api.soulsecure.lab` — `internal-tools` ที่เจอใน
lab นี้ทิ้ง hint ไว้ว่า "internal API base: /api/internal/" เอาไปใช้ต่อได้เลย
