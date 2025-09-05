# 🤖 Telegram Virus Scanner Bot

بوت لفحص الروابط باستخدام [VirusTotal API](https://www.virustotal.com/).

---

## 📝 المتطلبات

- **Python** >= 3.11
- المكتبات المطلوبة:
  - `python-telegram-bot==20.5`
  - `requests==2.31.0`
  - `python-dotenv==1.0.0`

---

## ⚡ تثبيت المشروع

1. **استنساخ المستودع:**
```bash
git clone https://github.com/username/telegram-bot.git
cd telegram-bot
```

2. **إنشاء بيئة افتراضية وتفعيلها:**
```bash
python -m venv venv

# على ويندوز
venv\Scripts\activate

# على لينكس/ماك
source venv/bin/activate
```

3. **تثبيت المكتبات المطلوبة:**
```bash
pip install -r requirements.txt
```

4. **إنشاء ملف `.env` وملئه بالمفاتيح:**
```
TELEGRAM_TOKEN=your_telegram_bot_token_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

5. **تشغيل البوت:**
```bash
python main.py
```

---

## 🔹 الأوامر المتاحة في البوت

| الأمر          | الوصف                                           |
|----------------|------------------------------------------------|
| `/start`       | بداية التشغيل وشرح البوت                        |
| `/help`        | المساعدة                                        |
| `/about`       | معلومات عن البوت                               |
| `/scan <رابط>` | فحص رابط محدد                                   |
| `/stats`       | عرض إحصائيات المستخدم                           |
| `/export`      | تصدير تقرير المستخدم                            |
| `/clear`       | مسح التقرير                                     |
| إرسال أي رابط مباشر | يتم فحصه تلقائيًا                             |

---

## 💡 ملاحظات مهمة

- **لا تقم برفع ملف `.env` إلى GitHub** لتجنب تسرب المفاتيح.
- جميع السجلات يتم حفظها في ملفات `logs_<user_id>.txt`.
- البوت يستخدم Telegram Bot API و VirusTotal API لفحص الروابط.

---

## 🛠️ نصائح لاحتراف المشروع

1. استخدام مجلد `logs/` لحفظ السجلات بدل وضعها في مجلد الجذر.
2. تحديث README دائمًا عند إضافة ميزات جديدة.
3. عند تشغيل البوت على Render أو أي سيرفر، ضع `.env` مباشرة على السيرفر.
4. إضافة ملف `LICENSE` (مثل MIT أو Apache) لتوضيح حقوق الاستخدام.

---

## 📌 روابط مفيدة

- [Telegram Bot API Documentation](https://core.telegram.org/bots/api)
- [VirusTotal API Documentation](https://developers.virustotal.com/)

