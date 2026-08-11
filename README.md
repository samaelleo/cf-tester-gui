# Cloudflare Clean IP Scanner (HE BGP API)
### اسکنر کراس‌پلتفرم و فوق‌سریع آی‌پی تمیز کلادفلر با تست تاخیر واقعی (RealDelay)

یک برنامه قدرتمند، مدرن و چندسکویی (Windows / Linux / macOS) برای استخراج زنده پیشوندهای آی‌پی کلادفلر از **Hurricane Electric BGP API** (`https://bgp.he.net/super-lg/report/api/v1/prefixes/originated/{as_number}`)، تست چندمرحله‌ای اتصال با انواع کانفیگ‌های پروکسی (VLESS, VMess, Trojan, Shadowsocks یا دامنه مستقیم)، و انجام **تست تاخیر واقعی (RealDelay Test)** از طریق هسته رسمی Xray.

---

## 📦 بسته‌های آماده دانلود (GitHub Releases)

با هر پوش جدید در مخزن گیت‌هاب، اکشن گیت‌هاب فایل‌های اجرایی زیر را به صورت خودکار بیلد کرده و در بخش **Releases** قرار می‌دهد:

| سیستم‌عامل | فرمت بسته | نام فایل در Releases |
| :--- | :--- | :--- |
| **ویندوز (Windows x64)** | `.exe` و `.zip` | `cf-clean-ip-scanner-windows-x64.exe` |
| **لینوکس (Linux / Debian / Ubuntu)** | `.deb` و `.tar.gz` | `cf-clean-ip-scanner_1.0.x_amd64.deb` |
| **مک (macOS Apple Silicon & Intel)** | `.dmg` و `.zip` | `cf-clean-ip-scanner-1.0.x-macos.dmg` |

---

## 🌟 قابلیت‌ها و ویژگی‌های کلیدی

1. **تست تاخیر واقعی (RealDelay Test با هسته Xray)**:
   - اجرای تست پینگ و تاخیر واقعی با ارسال یک درخواست واقعی HTTP به سرور مقصد از درون تونل پروکسی Xray.
   - نمایش میلی‌ثانیه واقعی تاخیر پروکسی (RealDelay) در یک ستون اختصاصی و مرتب‌سازی بر اساس آن.

2. **سازگاری کامل با ویندوز، لینوکس و مک (Cross-Platform)**:
   - **ویندوز (Windows)**: اجرای پنجره نیتیو با موتور Microsoft Edge WebView2 یا مرورگر پیش‌فرض.
   - **مک (macOS)**: اجرای نیتیو با WebKit Cocoa یا مرورگر.
   - **لینوکس (Linux)**: اجرای دسکتاپ (GTK/Qt)، وب یا حالت سرور اختصاصی بدون واسط گرافیکی (`--headless`).

3. **اتصال مستقیم به API شرکت Hurricane Electric (HE BGP Super-LG)**:
   - دریافت آنی تمام رنج‌های اختصاصی کلادفلر (بیش از ۵,۴۰۰ پیشوند برای `AS13335` و `AS209242`).
   - امکان وارد کردن هر شماره خودگردان (ASN) دلخواه به همراه fallback داخلی.

4. **پشتیبانی کامل از انواع پروتکل‌ها و کانفیگ‌ها**:
   - `vless://` (پشتیبانی کامل از WebSocket, gRPC, HTTPUpgrade, XHTTP/SplitHTTP, TLS, Reality, MLKEM768 Encryption)
   - `vmess://` (رمزگشایی و ساخت خودکار لینک جدید با آی‌پی سالم)
   - `trojan://` و `ss://`
   - وارد کردن مستقیم دامنه، ساب‌دامین یا ورکر کلادفلر

5. **تست چند مرحله‌ای و دقیق**:
   - **مرحله ۱**: تست زمان برقراری ارتباط TCP (TCP Ping)
   - **مرحله ۲**: تست TLS Handshake با SNI اختصاصی
   - **مرحله ۳**: تست ارتقای اتصال WebSocket/XHTTP و مسیر CDN
   - **مرحله ۴**: تست واقعی **Google Connectivity Check** (`http://connectivitycheck.gstatic.com/generate_204`) و محاسبه دقیق تاخیر زمانی (Latency).
   - **مرحله ۵**: **تست تاخیر واقعی (RealDelay)** از طریق هسته رسمی Xray-core.

6. **جدول زنده با مرتب‌سازی آنی (Live Sorting)**:
   - اضافه شدن لحظه‌ای آی‌پی‌های سالم به جدول به محض شناسایی.
   - مرتب‌سازی خودکار بر اساس کمترین پینگ گوگل یا تاخیر واقعی.

7. **امکانات کاربردی خروجی و ساخت کانفیگ جدید**:
   - کپی تکی یا دسته‌ای تمام آی‌پی‌های تمیز.
   - **ساخت و کپی مستقیم کانفیگ جدید**: تولید لینک آماده با قرار گرفتن آی‌پی تمیز به عنوان آدرس سرور و حفظ SNI/Host اصلی.
   - خروجی به فرمت‌های متنی (TXT)، جدول اکسل (CSV) و ساختار داده (JSON).

---

## 🚀 راهنمای نصب و اجرا در سیستم‌عامل‌های مختلف

### ۱. ویندوز (Windows)
- **روش اول (تک‌کلیک)**: فایل `run_app.bat` را دو بار کلیک کنید.
- **روش دوم (ترمینال)**:
  ```powershell
  pip install -r requirements.txt
  python main.py
  ```

### ۲. لینوکس (Linux - Ubuntu / Debian / Fedora / Arch)
```bash
pip install -r requirements.txt
chmod +x run_app.sh
./run_app.sh
```
*برای اجرا روی سرورهای VPS بدون مانیتور:*
```bash
python3 main.py --headless --host 0.0.0.0 --port 8080
```

### ۳. مک (macOS)
```bash
pip3 install -r requirements.txt
chmod +x run_app.sh
./run_app.sh
```
