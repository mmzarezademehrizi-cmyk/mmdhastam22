# Activity API — Cloudflare Worker + D1

همان API سامانه‌ی فعالیت (کاربران، اعضا، دسته‌بندی‌ها با روزهای هفته، ثبت ساعت، گزارش‌ها، محدودیت‌ها و نظارت مالک) که حالا روی **Cloudflare Workers** و دیتابیس **D1** اجرا می‌شود.

- آدرس API برای اپ‌ها: **`https://ymaos1475963.shop/appfaaliat`**
- مسیرها و پاسخ‌ها دقیقاً مثل سرور قبلی است؛ در اپ‌ها فقط `apiBaseUrl` عوض می‌شود.
- جدول‌های دیتابیس خودکار در اولین درخواست ساخته می‌شوند (نیازی به اسکریپت SQL نیست) و در آپدیت‌های بعدی داده‌ها دست‌نخورده می‌مانند.

## ۱) ساخت دیتابیس و رمزها (یک‌بار)

### راه الف — با پنل install-proje (بدون ترمینال)
1. تب **دیتابیس و حافظه** ← «ساخت D1» با نام `activity-db`.
2. تب **دیپلوی** ← مقصد «ورکر جدید» با نام `activity-api`، منبع GitHub (همین مخزن)، فایل اصلی `src/index.js`.
3. در بخش Binding اضافه کنید:

| نوع | نام | مقدار |
|---|---|---|
| D1 | `DB` | دیتابیس `activity-db` |
| رمز (Secret) | `APP_JWT_SECRET` | یک رشته‌ی تصادفی حداقل ۳۲ کاراکتر |
| رمز (Secret) | `SETUP_KEY` | یک رشته‌ی تصادفی حداقل ۱۲ کاراکتر |
| متغیر متنی | `BASE_PATH` | `/appfaaliat` |
| متغیر متنی | `SMS_PROVIDER` | `console` |

4. تب **دامنه و مسیر**: دامنه `ymaos1475963.shop` ← الگوی `ymaos1475963.shop/appfaaliat/*` ← ورکر `activity-api`.

### راه ب — با wrangler
```bash
npm install
npx wrangler login
npx wrangler d1 create activity-db         # database_id چاپ‌شده را در wrangler.jsonc بگذارید
npx wrangler secret put APP_JWT_SECRET
npx wrangler secret put SETUP_KEY
npx wrangler deploy                        # مسیر دامنه هم از wrangler.jsonc ثبت می‌شود
```

## ۲) ساخت مالک (یک‌بار)

```bash
curl -X POST https://ymaos1475963.shop/appfaaliat/setup/owner \
  -H "Content-Type: application/json" \
  -d '{"setupKey":"SETUP_KEY-شما","phone":"09121234567","password":"رمز-قوی-حداقل-8"}'
```

بعد از آن با همین شماره و رمز در اپ مالک وارد شوید. اگر رمز مالک را فراموش کردید، همین دستور با همان `SETUP_KEY` رمز را عوض می‌کند. وقتی لازم نیست، Secret به نام `SETUP_KEY` را حذف کنید تا این مسیر خاموش شود.

## ۳) تست

```bash
curl https://ymaos1475963.shop/appfaaliat/              # {"ok":true,...,"configured":true}
curl https://ymaos1475963.shop/appfaaliat/health        # {"ok":true}
```

اگر `configured:false` بود، یعنی D1 با نام `DB` یا Secret `APP_JWT_SECRET` وصل نشده است.

## ۴) تغییر در اپ‌ها
در `lib/config/app_config.dart` هر دو اپ:
```dart
static const String apiBaseUrl = 'https://ymaos1475963.shop/appfaaliat';
```
و دوباره build.

## تنظیمات اختیاری (Variables)

| نام | پیش‌فرض | توضیح |
|---|---|---|
| `BASE_PATH` | `/appfaaliat` | پیشوند مسیر. اگر Worker را روی کل دامنه یا زیردامنه می‌گذارید خالی بگذارید (`""`). |
| `SESSION_DAYS` | `30` | مدت اعتبار ورود |
| `SMS_PROVIDER` | `console` | `console` (آزمایشی) / `kavenegar` / `webhook` |
| `KAVENEGAR_API_KEY`, `KAVENEGAR_TEMPLATE` | — | برای کاوه‌نگار |
| `SMS_WEBHOOK_URL`, `SMS_WEBHOOK_AUTH` | — | برای وب‌هوک |
| `PBKDF2_ITERATIONS` | `100000` | سختی هش رمز (حداکثر مجاز Workers) |

## نکته‌های مهم

- **پلن Cloudflare:** هش کردن رمز CPU می‌خواهد. پلن رایگان سقف ۱۰ میلی‌ثانیه CPU دارد و ممکن است ورود با رمز گاهی خطا بدهد؛ پلن Workers Paid (حدود ۵ دلار در ماه) مشکلی ندارد. پلن رایگان همچنین سقف ۵۰ کوئری D1 در هر درخواست دارد (ثبت فعالیت با بیش از ~۴۰ نفر در یک‌بار به آن می‌خورد).
- **رمزهای قدیمی:** رمزهای سرور Node (scrypt) در Workers قابل بررسی نیستند. اگر داده‌ها را از سرور قبلی منتقل می‌کنید، مالک باید برای کاربران رمز جدید تعیین کند (اسکریپت انتقال: `scripts/export-from-sqlite.mjs`).
- **محدودیت تعداد درخواست** (ورود، OTP) برای هر نمونه‌ی Worker جداگانه است؛ قفل شدن حساب بعد از ۵ رمز اشتباه و فاصله‌ی ارسال کد OTP در دیتابیس ذخیره می‌شود و سراسری است.
- **پشتیبان:** D1 قابلیت Time Travel دارد (بازگردانی تا ۳۰ روز): `npx wrangler d1 time-travel info activity-db`.
- سرور Node قبلی را تا مطمئن شدن از کارکرد Worker خاموش نکنید.

## توسعه

```bash
npm install
npm test           # ۵۰ بررسی با D1 ساختگی
npm run dev        # اجرای محلی (فایل .dev.vars لازم است)
```
