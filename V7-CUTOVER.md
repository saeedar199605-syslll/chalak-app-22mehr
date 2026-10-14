# V7 — Cutover و Rollback کنترل‌شده

این دستورها آماده‌اند و روی Production اجرا نشده‌اند. مالک باید انتشار، انتقال داده و مقدار Smoke را جداگانه تأیید کند. دو مرجع مستقل هرگز هم‌زمان اجازه نوشتن وضعیت عملیاتی نداشته باشند.

| مرحله | شرط عبور | شکست: توقف و بازیابی |
|---|---|---|
| Freeze Writes | همه نسخه‌های قدیمی روی دامنه اصلی، pages.dev، URLهای Deployment/Preview، دسترسی مستقیم KV، سرویس‌ها و Importهای زمان‌بندی‌شده متوقف شوند. مسیرهای GET قدیمی نیز ممکن است Meta/Receipt بنویسند؛ تمام APIهای نسخه قدیمی باید از KV عملیاتی جدا شوند. Object جدید Frozen بماند. | نویسنده ناشناخته/فعال: توقف؛ KV مرجع قبلی بماند. Freeze در DO جلوی نسخه قدیمی را نمی‌گیرد. |
| Verified Backup | پس از توقف و همگرایی KV، State+Meta و آخرین Receipt/Revision معلوم بررسی شوند. دو برداشت باید برابر باشند. Backup اصلی بدون تغییر نگه‌داری شود؛ نسخه V7 جداگانه Seal/Verify شود. | Hash، تعداد یا رابطه ناسازگار: توقف؛ تعمیر خودکار یا کنارگذاشتن داده ممنوع. |
| Migration | فقط Worker/Pages مخصوص اپراتور در دسترس باشند. مقصد خالی و Frozen؛ Dry Run، سپس Migration صریح. | خطا: Gate بسته و مقصد Frozen؛ بررسی وضعیت و Receipt/Hash، بدون Retry کور. |
| Integrity Check | Export Frozen و Backup V7: Hash، Revision، کارکنان، ارزیابی‌ها، نمرات، نهایی‌شده‌ها، تخلفات/برگشت، Audit و Receiptها تطبیق دقیق داشته باشند. | عدم تطبیق: Authority فعال نشود؛ پیش از پذیرش داده جدید، KV قبلی دست‌نخورده قابل برگشت است. |
| Switch Authority | تمام Pages Functions فعال به همان Worker/Namespace و Object `chalak-authoritative-state-v1` بروند. Binding/Secretهای موجود حفظ شوند؛ مسیر KV عملیاتی قدیمی بسته بماند. | اتصال/تنظیمات ناسازگار: Gate بسته؛ کد و تنظیمات قبلی زیر Gate بازگردند. |
| Smoke | Gate عمومی بسته؛ فقط Admin آزمایشگر مجاز. Activate در Revision تأییدشده؛ مقدار مجاز → ACK/Receipt → Reload → خواندن تازه از سرور. | 503/نتیجه نامطمئن: همان Operation ID از Receipt بررسی شود؛ DO Freeze. بعد از Commit جدید فقط Export تازه مبنای Rollback است. |
| Enable Writes | تطبیق و Smoke موفق، تأیید مالک و اثبات توقف تمام نویسندگان قدیمی. | خطا: Gate دوباره بسته؛ DO Freeze؛ Export تازه و Rollback کنترل‌شده. |

Freeze با تنظیم یک متغیر ادعایی تأیید نمی‌شود. اپراتور باید تمام Hostها/URLها و مصرف‌کنندگان KV را فهرست کند، قواعد Gate و توقف Jobها را بررسی کند و در مرحله کنترل‌شده ثابت کند درخواست مجاز هیچ Commit ایجاد نمی‌کند. Hash، Revision و Receipt بعد از درخواست‌های کنترل‌شده و همگرایی KV ثابت بمانند. انجام این بررسی‌های تغییردهنده نیازمند مجوز مالک است؛ در Preflight خواندنی انجام نمی‌شوند.

Token نگهداری فقط از `CHALAK_MAINTENANCE_TOKEN` خصوصی خوانده می‌شود. `URL` نشانی Pages محدودشده به اپراتور و `REV` عدد تازه‌خوانده‌شده است.

```text
node tools/state-transfer.mjs seal STATE.json META.json BACKUP-V7.json
node tools/state-transfer.mjs verify BACKUP-V7.json
node tools/state-transfer.mjs dry-run URL BACKUP-V7.json
node tools/state-transfer.mjs migrate URL BACKUP-V7.json --execute
node tools/state-transfer.mjs export URL REV MIGRATED.json
node tools/state-transfer.mjs verify MIGRATED.json
node tools/state-transfer.mjs activate URL REV --execute
```

V7 فقط قالب مجموعه Receipt را یکسان می‌کند: نبود مجموعه → آرایه خالی؛ ترتیب Receiptها → Operation ID. کارکنان، نمرات، Audit و Revision تغییر نمی‌کنند. Hash اصلی Backup قبلی **پیش از** این تبدیل کنترل می‌شود؛ Hash خراب رد می‌شود. Hash نسخه Canonical ممکن است با Backup قدیمی فاقد Receipt یا دارای ترتیب متفاوت فرق کند؛ Backup اصلی حفظ شود و کنترل Migration با Hash Canonical صریح انجام شود. Migration تکراری همان Snapshot هیچ رکوردی اضافه نمی‌کند.

## بازگشت پس از پذیرش داده جدید

```text
node tools/state-transfer.mjs freeze URL CURRENT_REV --execute
node tools/state-transfer.mjs export URL CURRENT_REV FRESH_BACKUP.json
node tools/state-transfer.mjs verify FRESH_BACKUP.json
node tools/state-transfer.mjs rollback-kv FRESH_BACKUP.json RESTORE_BULK.json
```

دستور آخر فقط فایل آماده می‌کند. مالک باید برگرداندن **Export تازه** به KV قبلی را تأیید کند؛ State و Meta هر دو بازیابی شوند. پیش از بازکردن Gate، خواندن تازه KV، Hash/Revision و تمام تعدادها بررسی شوند و کد/تنظیمات کامل قبلی بازگردند. اگر Export یا تطبیق ناموفق است، Gate بسته بماند و بازگشت انجام نشود. پس از Commit جدید، Backup قدیمیِ قبل از Cutover ممنوع است. هنگام فعال‌شدن KV، DO Frozen بماند؛ SQLite Namespace و سوابق جدید حذف نشوند.
