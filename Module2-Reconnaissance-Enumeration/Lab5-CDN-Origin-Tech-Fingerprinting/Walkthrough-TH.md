# Module 2 — Lab 5: CDN, Origin & Technology Fingerprinting — เดินเกมส์แบบละเอียด (ภาษาไทย)

ไฟล์นี้เป็น **transcript จริงของลำดับขั้นตอน** ไล่เก็บให้ครบทั้ง 4 flags ของ Lab 5 —
แลปสุดท้ายของ Module 2 ใช้ทั้ง **HTTP(S) Request Tool** (การ์ดที่ 6) และการ์ด
**"Passive DNS History"** (โผล่เฉพาะตอนเล่นถึง Lab 5) ใน Recon Toolkit

**Target IP ตอนนี้:** `192.168.174.139` (เปลี่ยนทุกครั้งที่ VM รีสตาร์ท ให้เช็คกับ
ผู้สอนก่อนเริ่ม)

**ก่อนเริ่ม:** ต้องตั้ง DNS + trust CA ไว้แล้ว (ดูขั้นที่ 0 ใน
[Lab 1 Walkthrough](../Lab1-CloudAssetDiscovery/Walkthrough-TH.md))

**สถานการณ์:** เก็บครบ 4 lab แล้ว มีรายชื่อ host/service เกือบครบทั้งองค์กร เหลือ
เรื่องเดียว — สิ่งที่ยิงไปตอนนี้ทั้งหมด **ยิงผ่าน CDN อยู่หรือเปล่า?** และถ้าใช่
เซิร์ฟเวอร์ตัวจริงที่ซ่อนอยู่ข้างหลังอยู่ตรงไหน — เพราะ origin server มักไม่มี
protection ระดับเดียวกับที่ CDN บังคับใช้ (WAF, rate limit) การเจอ origin ตรงๆ คือ
finding มูลค่าสูงสุดอย่างหนึ่งในงาน pentest จริง

---

## ขั้นที่ 1: Fingerprint CDN ที่ edge (`www`)

เปิด `http://192.168.174.139:9091/` ไปที่การ์ดที่ 6 **"HTTP(S) Request Tool"**:

1. **Hostname:** `www.soulsecure.lab`
2. **Method:** HEAD (หรือ GET ก็ได้ แค่จะดู header)
3. **Path:** `/`
4. กด **Send Request**

ผลลัพธ์ headers ที่ต้องสังเกต:
```
Server: nginx/1.31.3
Server: SoulSecure-CDN
Age: 117
X-Cache: HIT
```

**จุดสำคัญ:** `Age` (วินาทีที่ cache เก็บไว้) กับ `X-Cache: HIT/MISS` เป็น header ที่
**ไม่มีความหมายอะไรเลยสำหรับ origin server จริง** (origin สร้าง response ใหม่ทุกครั้ง
ไม่มี cache) — แค่มี header พวกนี้อยู่ก็เป็นสัญญาณ CDN ชัดเจนแล้ว ไม่ต้องสนใจค่า
ตัวเลขด้วยซ้ำ

**อีกจุดที่แปลก:** เจอ `Server` header **2 อัน** ในการตอบเดียวกัน — นี่ไม่ใช่บั๊กของ
lab แต่เป็นเรื่องที่เกิดจริงในโลกจริง เวลา CDN/reverse proxy ลืม strip header
`Server` เดิมของ origin ก่อนส่งต่อ ทำให้ software banner ของเครื่องจริงหลุดผ่าน CDN
มาด้วย — เก็บไว้เป็น finding ได้เลย

## ขั้นที่ 2: เช็ค `robots.txt` และ `security.txt`

**2.1 — `robots.txt`:** เปลี่ยน Method กลับเป็น GET, Path เป็น `/robots.txt`

```
User-agent: *
Disallow: /staging-notes/
Disallow: /internal-tools/
Disallow: /api/internal/
```

**สำคัญ:** `Disallow` เป็นแค่คำขอให้ search engine ไม่ index หน้านั้น **ไม่ใช่การกัน
access** — เข้าตรงๆ ได้ปกติ ต้องไปดูทุกอันที่ระบุไว้

**2.2 — `security.txt`:** Path เป็น `/.well-known/security.txt`

```
Contact: mailto:security@soulsecure.lab
Expires: 2027-01-01T00:00:00.000Z
Preferred-Languages: en, th
Canonical: https://www.soulsecure.lab/.well-known/security.txt
# build artifacts are served from /assets/js/ -- please don't scan these,
# they're just static bundles (dev note, left in by mistake)
```

comment สุดท้ายไม่ควรอยู่ในไฟล์นี้เลย — เป็นโน้ตภายในที่หลุดออกมา บอกตรงๆ ว่ามี JS
bundle อยู่ที่ `/assets/js/` (ใช้ต่อขั้นที่ 5)

## ขั้นที่ 3: เข้าไปดู path ที่ `robots.txt` บอกไว้ → Flag 2

**Path:** `/staging-notes/` Send Request:

```html
<h2>staging-notes (internal)</h2>
<p>disallowed in robots.txt -- that's a hint for search engines, not access control.</p>
<ul>
<li>CDN in front of www: yes (see response headers -- Age/X-Cache only appear through
    the CDN, never hitting the origin directly)</li>
<li>origin bypass note-to-self: don't forget origin-direct.soulsecure.lab is still
    open, meant to close it after migration</li>
</ul>
<!-- flag: flag{d79d7cee7f1e1f4bcdc26fcee00ce18a} -->
```

**จุดสำคัญที่สุดของขั้นนี้:** หน้านี้บอกชื่อ origin server ตรงๆ เลยว่า
`origin-direct.soulsecure.lab` — เก็บชื่อนี้ไว้ใช้ขั้นที่ 6 (ถ้าไม่เจอบรรทัดนี้ก็ยัง
หาชื่อเดียวกันได้อีกทางผ่าน DNS history ในขั้นที่ 5)

## ขั้นที่ 4: อ่าน JS bundle จริง → Flag 4 (harder mode)

**Path:** `/assets/js/main.js` (ตามที่ `security.txt` บอกไว้ในขั้นที่ 2.2) Send
Request:

```js
/* SoulSecure CloudStack UI v3.2 - built with vue-cli */
/* eslint-disable */
!function(){"use strict";console.log("soulsecure ui bootstrapped")}();
// TODO(dev): rotate this before GA, hardcoded for the staging demo only
const INTERNAL_API_TOKEN = "sk_internal_soulsecure_9f2c7a1e4b6d8801";
// flag: flag{6f15fea713da8d4e53e704437a6b436a}
```

JavaScript ที่ส่งไปฝั่ง browser คือ **โค้ดที่ทุกคนอ่านได้เต็มๆ เสมอ** — token/secret ที่
ฝังไว้ตรงๆ (hardcode) เป็น finding ที่เจอบ่อยมากในงานประเมินจริง

## ขั้นที่ 5: หาชื่อ origin server ในอดีตผ่าน Passive DNS History

เลื่อนลงล่างสุดของหน้า `http://192.168.174.139:9091/` จะเจอการ์ด **"Passive DNS
History"** (โผล่เฉพาะตอนนี้ที่เป็น Lab 5 แล้วเท่านั้น):

1. **Domain:** `www.soulsecure.lab` (ค่า default อยู่แล้ว)
2. กด **Look up history**

```json
{
  "domain": "www.soulsecure.lab",
  "history": [
    {"date": "2025-01-10", "type": "A", "value": "(behind CDN as of this date)"},
    {"date": "2024-06-02", "type": "CNAME", "value": "origin-direct.soulsecure.lab"},
    {"date": "2023-11-20", "type": "A", "value": "origin-direct.soulsecure.lab (pre-CDN, direct origin)"}
  ]
}
```

ชื่อ `origin-direct.soulsecure.lab` โผล่ซ้ำ 2 ครั้ง (ครั้งแรกเป็น CNAME target,
ครั้งก่อนหน้านั้นเป็น A record ตรงๆ ก่อนจะมี CDN) — ตรงกับชื่อที่เจอใน
`staging-notes` ขั้นที่ 3 พอดี ยืนยันแหล่งข้อมูล 2 ทางตรงกัน

## ขั้นที่ 6: บายพาส CDN เข้า origin ตรงๆ → Flag 1

ใช้เทคนิคเดียวกับ Lab 2 (vhost brute force ไม่ต้องพึ่ง DNS จริง — ชื่อ
`origin-direct` ไม่มี DNS record ในปัจจุบันแล้ว):

1. **Hostname:** `origin-direct.soulsecure.lab`
2. **Method:** GET
3. **Path:** `/`
4. Send Request

```
flag{8290248cac3247ccf5288ee3f79e39c7}
```

**ขั้นเปรียบเทียบ (สำคัญมากสำหรับ deliverable):** เปลี่ยน Method เป็น HEAD แล้ว Send
Request อีกครั้งด้วย Hostname เดิม เทียบ header กับขั้นที่ 1:

```
Server: nginx/1.31.3
X-Debug-Mode: true
```

สังเกตว่า **ไม่มี** `Server: SoulSecure-CDN`, **ไม่มี** `Age`, **ไม่มี** `X-Cache` เลย
— พิสูจน์ชัดเจนว่านี่คือ origin ตัวจริง ไม่ได้ผ่าน CDN แถมยังมี `X-Debug-Mode: true`
หลุดออกมาด้วย (debug mode เปิดค้างไว้บนเครื่อง production)

## ขั้นที่ 7: ทดสอบว่ามี WAF อยู่หน้าด่านไหม (ไม่มี flag — เทคนิคเท่านั้น)

Brute-force vhost อีกชื่อ (`search`, ไม่มี DNS เหมือนกัน) แล้วยิง 2 คำขอเทียบกัน —
ปกติกับ payload แบบ SQLi canary:

**คำขอปกติ:**
1. **Hostname:** `search.soulsecure.lab`
2. **Path:** `/search?q=hello`
3. Send Request → `HTTP 200 OK`

**คำขอ canary:**
1. **Path:** `/search?q=1%20union%20select%20password%20from%20users`
2. Send Request → `HTTP 403 Forbidden`

response ที่ต่างกันชัดเจน (200 กับ 403) ระหว่างคำขอปกติกับ payload ที่ดูเหมือนโจมตี
คือสัญญาณว่ามี **WAF** อยู่หน้าด่าน — เป็นสิ่งแรกๆ ที่ต้องเช็คก่อนยิง payload จริงใน
งานประเมิน เพราะ WAF อาจบล็อกหรือแจ้งเตือนก่อนที่ payload จะไปถึงเป้าหมายจริงด้วยซ้ำ

## ขั้นที่ 8: ยั่วให้ API หลุด tech fingerprint → Flag 3

ยิง path ที่มั่นใจว่าไม่มีอยู่จริงไปที่ `api.soulsecure.lab`:

1. **Hostname:** `api.soulsecure.lab`
2. **Path:** `/doesnotexist` (หรือ path มั่วอะไรก็ได้ที่ไม่มีจริง)
3. Send Request

```json
{
  "error": "Not Found",
  "flag": "flag{ea97648f7c958c3e5c750862b4ab4519}",
  "powered_by": "SoulSecure API Gateway (Flask 3.x / Python 3.12, Gunicorn behind ALB)"
}
```

custom error handler บอกเทคโนโลยีเบื้องหลังตรงๆ (framework, ภาษา, runtime, และแม้แต่
ว่าอยู่หลัง ALB) — error handler ที่ verbose เกินไปเป็นแหล่ง fingerprint ชั้นดีเสมอ

---

## สรุป: ครบ 4 Flags ของ Lab 5 (และ Module 2 ทั้งหมด — 20 flags)

| # | จุดที่เจอ | วิธีหา | Flag |
|---|---|---|---|
| 1 | `origin-direct.soulsecure.lab` | DNS history + staging-notes hint → บายพาส CDN | `flag{8290248cac3247ccf5288ee3f79e39c7}` |
| 2 | `/staging-notes/` | เจอจาก `robots.txt` | `flag{d79d7cee7f1e1f4bcdc26fcee00ce18a}` |
| 3 | API 404 handler | ยิง path ที่ไม่มีจริงไปที่ `api.soulsecure.lab` | `flag{ea97648f7c958c3e5c750862b4ab4519}` |
| 4 ⭐ | `/assets/js/main.js` | เจอจาก `security.txt` | `flag{6f15fea713da8d4e53e704437a6b436a}` |

**เช็คทั้ง 4 flag รวดเดียวผ่าน command line:**
```bash
echo "--- Flag 1 (origin bypass) ---"; curl -sk --resolve origin-direct.soulsecure.lab:443:192.168.174.139 https://origin-direct.soulsecure.lab/ | grep -o 'flag{[^}]*}'
echo "--- Flag 2 (staging-notes) ---"; curl -sk https://www.soulsecure.lab/staging-notes/ | grep -o 'flag{[^}]*}'
echo "--- Flag 3 (api 404) ---"; curl -sk https://api.soulsecure.lab/doesnotexist | grep -o 'flag{[^}]*}'
echo "--- Flag 4 (js leak) ---"; curl -sk https://www.soulsecure.lab/assets/js/main.js | grep -o 'flag{[^}]*}'
```

## หมายเหตุ

- **Deliverable ของ lab นี้ไม่ใช่แค่ 4 flag** — ต้องส่งตาราง "CDN/Origin comparison"
  (เทียบ header ของ `www` กับ `origin-direct`) และ **final consolidated asset
  inventory** ที่รวมทุกอย่างจาก Lab 1-5 เข้าด้วยกันเป็นตารางเดียว นี่คือ deliverable
  ของทั้ง Module 2 ไม่ใช่แค่ของ lab นี้
- Card "Passive DNS History" ใน OSINT Sandbox โผล่เฉพาะตอน `LAB_LEVEL >= 5` เท่านั้น
  — ถ้าเล่น Lab 1-4 มาก่อนจะไม่เห็นการ์ดนี้ ปกติ
- ตัวอย่าง `security.txt` ที่มีคอมเมนต์หลุดแบบนี้ และ header `Server` ซ้อนกัน 2 อัน
  ล้วนเป็นรูปแบบความผิดพลาดที่พบได้จริงในองค์กรจริง ไม่ใช่การจัดฉากเกินจริง

## Module 2 จบแล้ว — สรุป 20 flags ทั้งหมด

ดูรายการ flag ครบทั้ง 5 labs ได้ที่
[Flags-สรุปทั้งหมด.md](../Flags-สรุปทั้งหมด.md)

## ต่อไป

Module 3 (Initial Access & Storage Exploitation) เริ่มจากใช้ประโยชน์จาก bucket
`soulsecure-prod-assets` ที่ยัง public อยู่ตั้งแต่ Lab 4 — จากแค่ "อ่านได้" ไปสู่
"เข้าถึงระบบจริง"
