# Module 2 — Lab 4: Object Storage Enumeration — เดินเกมส์แบบละเอียด (ภาษาไทย)

ไฟล์นี้เป็น **transcript จริงของลำดับขั้นตอน** ไล่เก็บให้ครบทั้ง 4 flags ของ Lab 4 —
ใช้การ์ดที่ 6 **"HTTP(S) Request Tool"** ใน Recon Toolkit เป็นหลัก (Method = GET
ทุกขั้นตอน ไม่ต้องยุ่งกับ Headers/Body เลย)

**Target IP ตอนนี้:** `192.168.174.136` (เช็คกับผู้สอนทุกครั้งที่เปิดเครื่องใหม่)

**ก่อนเริ่ม:** ต้องตั้ง DNS + trust CA ไว้แล้ว (ดูขั้นที่ 0 ใน
[Lab 1 Walkthrough](../Lab1-CloudAssetDiscovery/Walkthrough-TH.md))

**สถานการณ์:** Lab 1 มี HTML comment หลุดชื่อ bucket `soulsecure-prod-assets` พร้อม
TODO "ทำให้ private ก่อน launch" — ซึ่งไม่มีใครทำ งานคือเอาชื่อนี้ไปขยายผลหา bucket
อื่นที่เกี่ยวข้อง

---

## ขั้นที่ 1: ยืนยัน bucket ที่รู้อยู่แล้ว

เปิด `http://192.168.174.136:9091/` ไปที่การ์ดที่ 6 **"HTTP(S) Request Tool"**:

1. **Hostname:** `storage.soulsecure.lab`
2. **Method:** GET
3. **Path:** `/soulsecure-prod-assets/`
4. กด **Send Request**

ผลลัพธ์ `HTTP 200` พร้อม XML `ListBucketResult` แสดงว่า bucket นี้ **public และ list
ได้** มี 3 object: `README.txt`, `logo.png`, `config/backup-2026-07-01.json`

## ขั้นที่ 2: Permutation — เดาชื่อ bucket จากรูปแบบที่พบบ่อย

ลองเปลี่ยนแค่ช่อง **Path** ไล่ทีละชื่อ (Hostname/Method เดิม) แล้วดู **HTTP status**
ที่มุมซ้ายบนของผลลัพธ์ทุกครั้ง:

| Path ที่ลอง | Status | ความหมาย |
|---|---|---|
| `/soulsecure-prod-assets/` | 200 | มีอยู่จริง + public (ทำไปแล้วขั้นที่ 1) |
| `/soulsecure-dev-assets/` | **403** | **มีอยู่จริง แต่เข้าไม่ได้** ← สำคัญมาก |
| `/soulsecure-staging-assets/` | **404** | ไม่มี bucket นี้อยู่จริง |
| `/soulsecure-backups-eu/` | 200 | มีอยู่จริง + public → ไปขั้นที่ 4 |
| `/soulsecure-terraform-state/` | 200 | มีอยู่จริง + public → ไปขั้นที่ 5 |

**จุดสำคัญที่สุดของ lab นี้:** อย่าดูแค่ "404 หรือไม่ใช่ 404" — ต้องแยกให้ออกระหว่าง
**403 (AccessDenied)** กับ **404 (NoSuchBucket)** เพราะความหมายต่างกันคนละเรื่อง:
- `403` = bucket **มีอยู่จริง** แค่ไม่มีสิทธิ์เข้า (นี่คือ finding สำคัญเช่นกัน แม้จะ
  เข้าไฟล์ไม่ได้เลยก็ตาม — ยืนยันว่าองค์กรเป็นเจ้าของชื่อนี้แน่ๆ)
- `404` = ไม่มี bucket ชื่อนี้อยู่เลย

## ขั้นที่ 3: อ่าน config ใน prod-assets → Flag 1

กลับไป Path `/soulsecure-prod-assets/config/backup-2026-07-01.json` (สังเกตว่า
`config/` เป็นแค่ prefix ของชื่อไฟล์ ไม่ใช่ "โฟลเดอร์" จริงใน S3) Send Request:

```json
{
  "db_host": "prod-db.internal.soulsecure.lab",
  "db_user": "soulsecure_app",
  "db_password": "Sup3rS3cretProdPW!",
  "stripe_api_key": "sk_live_51HFAKESOULSECUREDONOTUSE0000",
  "flag": "flag{c3909083d936385564ffe54a86c340b9}"
}
```

## ขั้นที่ 4: โกยของจาก backups-eu → Flag 2

**Path:** `/soulsecure-backups-eu/db-snapshot-notes.txt` Send Request:

```
Nightly snapshot notes -- backup-eu region
Retention: 30 days
flag{bb244e7d9025c5600bdc019ad5c726dc}
```

(ชื่อ bucket นี้เชื่อมโยงกับ `backup-eu.soulsecure.lab` ที่เจอตั้งแต่ Lab 1)

## ขั้นที่ 5: โกยของจาก terraform-state → Flag 3

**Path:** `/soulsecure-terraform-state/terraform.tfstate` Send Request:

```json
{
  "outputs": {
    "vpc_id": {"value": "vpc-0fake1234567890ab"},
    "rds_endpoint": {"value": "prod-db.internal.soulsecure.lab:5432"},
    "deploy_role_access_key": {"value": "AKIAFAKESOULSECURE02"}
  },
  "flag": "flag{e21e4a4043ae07729741ef42be7dc9af}"
}
```

**ทำไมสำคัญ:** ชื่อ bucket ลงท้ายด้วย `-state`/`-tfstate` เป็นรูปแบบที่นิยมใช้จริง
สำหรับเก็บ Terraform remote state — ถ้าเจอในงานจริงต้องรายงานเป็น critical finding
เพราะไฟล์ state มักมี secret ของทั้งระบบ infrastructure อยู่ข้างใน

## ขั้นที่ 6: ไม่ใช่ทุกอย่างเป็น AWS → Flag 4 (harder mode)

SoulSecure ไม่ได้ใช้แค่ S3 — Google Cloud Storage มี URL รูปแบบเฉพาะตัวคือ
`/storage/v1/b/<bucket>/o` (list) และ `/storage/v1/b/<bucket>/o/<object>?alt=media`
(ดาวน์โหลดไฟล์) **hostname เดียวกันเป๊ะ** (`storage.soulsecure.lab`) แค่ path คนละ
รูปแบบ

**ขั้นแรก — list ดูว่ามีอะไรบ้าง:**
- **Path:** `/storage/v1/b/soulsecure-gcs-assets/o`
- Send Request

```json
{"items":[{"bucket":"soulsecure-gcs-assets","name":"notes/migration-plan.txt","size":"152"}],"kind":"storage#objects"}
```

**ขั้นสอง — ดึงเนื้อไฟล์:**
- **Path:** `/storage/v1/b/soulsecure-gcs-assets/o/notes%2Fmigration-plan.txt?alt=media`

  ⚠️ ต้อง URL-encode เครื่องหมาย `/` ในชื่อไฟล์เป็น `%2F` (จาก `notes/migration-plan.txt`
  กลายเป็น `notes%2Fmigration-plan.txt`) และต้องมี `?alt=media` ต่อท้ายด้วย ไม่งั้นจะ
  ได้แค่ metadata ไม่ใช่เนื้อไฟล์จริง
- Send Request

```
Migration notes: moving remaining prod assets from S3 to GCS by end of quarter.
flag{b091f26222ff3e2e245ee90a35927202}
```

---

## สรุป: ครบ 4 Flags ของ Lab 4

| # | Bucket | สถานะ | Flag |
|---|---|---|---|
| 1 | `soulsecure-prod-assets` (config file) | public | `flag{c3909083d936385564ffe54a86c340b9}` |
| 2 | `soulsecure-backups-eu` | public | `flag{bb244e7d9025c5600bdc019ad5c726dc}` |
| 3 | `soulsecure-terraform-state` | public | `flag{e21e4a4043ae07729741ef42be7dc9af}` |
| 4 ⭐ | `soulsecure-gcs-assets` (GCS-style path) | public | `flag{b091f26222ff3e2e245ee90a35927202}` |

**เช็คทั้ง 4 flag รวดเดียวผ่าน command line:**
```bash
echo "--- Flag 1 ---"; curl -sk https://storage.soulsecure.lab/soulsecure-prod-assets/config/backup-2026-07-01.json | grep -o 'flag{[^}]*}'
echo "--- Flag 2 ---"; curl -sk https://storage.soulsecure.lab/soulsecure-backups-eu/db-snapshot-notes.txt | grep -o 'flag{[^}]*}'
echo "--- Flag 3 ---"; curl -sk https://storage.soulsecure.lab/soulsecure-terraform-state/terraform.tfstate | grep -o 'flag{[^}]*}'
echo "--- Flag 4 ---"; curl -sk "https://storage.soulsecure.lab/storage/v1/b/soulsecure-gcs-assets/o/notes%2Fmigration-plan.txt?alt=media" | grep -o 'flag{[^}]*}'
```

## หมายเหตุ

- **`soulsecure-dev-assets` (403) กับ `soulsecure-staging-assets` (404)** ไม่มี flag
  ทั้งคู่ แต่ต้องบันทึกลง deliverable table ด้วยเสมอ — โจทย์ต้องการฝึกแยก "มีอยู่จริง
  แต่เข้าไม่ได้" ออกจาก "ไม่มีอยู่เลย" ไม่ใช่แค่ไล่หา flag อย่างเดียว
- Path `config/backup-2026-07-01.json` **ไม่ใช่โฟลเดอร์จริง** — Object Storage (S3/GCS)
  ไม่มีโฟลเดอร์แท้ๆ ทุกอย่างเป็น "key" แบนๆ ที่มี `/` อยู่ในชื่อ แค่ทำให้ดูเหมือน
  โครงสร้างไดเรกทอรีเฉยๆ

## ต่อไป

Lab 5 (CDN, Origin & Technology Fingerprinting) เป็น lab สุดท้ายของ Module 2 —
รวบรวมทุกอย่างจาก Lab 1-4 มาทำ asset inventory ฉบับสมบูรณ์ พร้อมหา origin server
ตัวจริงที่ซ่อนอยู่หลัง CDN
