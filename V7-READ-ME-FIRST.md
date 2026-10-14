# CHALAK PERFORMANCE V7 FINAL

این بسته شامل دو سرویس است. انتشار Frontend به‌تنهایی Backend تراکنشی را راه‌اندازی نمی‌کند. Production در این تحویل بررسی یا تغییر نشده است.

| مسیر در FINAL.zip | کاربرد |
|---|---|
| `pages/` | Frontend ساخته‌شده، Assets، Functions در `_worker.js/index.js` و تنظیمات Pages |
| `worker/` | Worker ساخته‌شده، کلاس `ChalakState` و Migration SQLite |
| `scripts/` | بررسی محلی، Preflight خواندنی و انتشار با توقف در خطا |
| `tools/state-transfer.mjs` | Backup، Verify، Dry Run، Migration، Freeze، Export و آماده‌سازی Rollback |
| `artifact-hashes.json` | Hash فایل‌های اجرایی و تنظیمات بسته |

## مسیر واحد انتشار

1. `FINAL.zip` را در پوشه‌ای مستقل باز کنید. Node.js24 و دسترسی npm لازم است. `npm ci` سپس `npm run verify` را اجرا کنید. نسخه ابزار ثابت Wrangler4.131.2 است.
2. مالک، حساب و **نام واقعی پروژه Pages موجود** را تعیین کند. `CLOUDFLARE_ACCOUNT_ID`، `CHALAK_PAGES_PROJECT` و `CLOUDFLARE_API_TOKEN` فقط در محیط خصوصی فرایند تنظیم شوند؛ Token در فایل انتشار یا پیام قرار نگیرد. اسکریپت هیچ پروژه یا Namespace KV جدیدی خودکار نمی‌سازد.
3. `npm run preflight` فقط درخواست GET می‌فرستد و فقط نام Secretها را گزارش می‌کند. نام پروژه، KV، Worker، کلاس، Namespace SQLite، Migration و Bindingهای Production/Preview باید با تنظیمات زنده تطبیق داشته باشند. Binding یا متغیر اضافیِ ناشناخته باعث توقف می‌شود؛ حذف آن برای عبور از کنترل مجاز نیست. برای تهیه تنظیمات موجود از راهنمای Cloudflare استفاده کنید؛ فایل زنده را روی سورس معتبر بازنویسی نکنید.
4. Preview به‌صورت پیش‌فرض Binding داده ندارد و بسته می‌ماند. برای استفاده از Preview، مالک باید KV و Worker جداگانه را در تنظیمات بازبینی‌شده تعیین کند. اتصال Preview به مرجع Production ممنوع است.
5. فقط با اجازه مالک، مراحل `V7-CUTOVER.md` اجرا شوند. بعد از اثبات توقف همه نویسندگان قدیمی، اپراتور `CHALAK_LEGACY_WRITES_FROZEN=YES` را تنظیم می‌کند. این متغیر خودش نویسندگان را متوقف نمی‌کند.
6. با مجوز مستقل انتشار Worker: `npm run deploy:worker -- --owner-approved`. کلاس/Namespace قبلی تغییر نام یا حذف نشود. برای Worker تازه، مالک نام Secret مستقل `STORAGE_MAINTENANCE_TOKEN` را در Cloudflare ایجاد کند؛ مقدار از حداقل32 نویسه تصادفی تشکیل شود. اسکریپت Secret را ایجاد یا تغییر نمی‌دهد.
7. Preflight دوباره انجام شود. پس از Backup و آماده‌سازی Migration زیر Gate، با مجوز انتشار Pages: `npm run deploy:pages -- --owner-approved`. انتشار اسکریپت، Migration یا فعال‌سازی نوشتن را خودکار اجرا نمی‌کند.
8. مطابق Runbook، تطبیق داده، Smoke و تأیید مالک قبل از بازکردن Gate انجام شوند. `/release.json` نسخه7.0.0 و `/api/health` مرجع `sqlite-durable-object` با نسخه7.0.0 را نشان دهند؛ وجود HTTP200 Frontend به‌تنهایی کافی نیست.

Secretهای فعلی Pages مانند `ADMIN_PASSWORD` و Secretهای قابلیت‌های فعال Gemini/Email باید حفظ شوند. Worker به KV احراز هویت متصل است؛ Secretهای Pages را بی‌دلیل به Worker تکثیر نکنید. Preflight موجودبودن نام `ADMIN_PASSWORD` را می‌خواهد؛ محیطی که فقط Credential ذخیره‌شده دارد، تا بررسی صریح روش ورود، متوقف می‌شود. برای Worker از `--keep-vars` استفاده می‌شود و Binding اضافی ناشناخته باعث توقف است. حفظ واقعی تنظیمات زنده تا دسترسی مالک تأیید نشده است.

تغییر ضروری تنظیمات، نیازمند بازبینی مالک و ثبت مجدد Hash محلی با `node scripts/release.mjs seal-artifacts` است؛ کد اجرایی بسته تغییر نکند. خطا فرایند را متوقف می‌کند؛ Retry خودکار یا Rollback خودکار وجود ندارد.

## SOURCE.zip

سورس از v6.2 با Hash پذیرفته‌شده استخراج شده و اصل v6.2 تغییر نکرده است. برای بازسازی: `npm ci` → `npm run typecheck` → `npm run build` → `npm run storage:tool` → `npm run release:prepare`. پوشه `release/` خروجی همان مسیر انتشار است. هیچ `.dev.vars` آزمایشی هنگام آماده‌سازی بسته حاضر نباشد. تست‌های هدفمند در `tests/v7-acceptance.ts` هستند؛ روی Production اجرا نشوند.

راهنمای تنظیمات و ساختار دو سرویس: [Pages Wrangler](https://developers.cloudflare.com/pages/functions/wrangler-configuration/)، [Pages Durable Object bindings](https://developers.cloudflare.com/pages/functions/bindings/)، [Advanced mode](https://developers.cloudflare.com/pages/functions/advanced-mode/).
