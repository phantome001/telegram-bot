# Telegram Virus Scanner Bot

🤖 بوت لفحص الروابط باستخدام [VirusTotal API](https://www.virustotal.com/).

---

## المتطلبات

- Python >= 3.11
- مكتبات Python المطلوبة:
  - python-telegram-bot==20.5
  - requests==2.31.0
  - python-dotenv==1.0.0

---

## تثبيت المشروع

1. استنساخ المستودع:
```bash
git clone https://github.com/username/telegram-bot.git
cd telegram-bot

2-إنشاء بيئة افتراضية وتفعيلها:
python -m venv venv
# على ويندوز
venv\Scripts\activate
# على لينكس/ماك
source venv/bin/activate

3-تثبيت المكتبات:
pip install -r requirements.txt

4-إنشاء ملف .env وملئه بالمفاتيح:
TELEGRAM_TOKEN=your_telegram_bot_token_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

تشغيل البوت
python main.py

-------------------------------------------------------------------

الأوامر المتاحة في البوت

/start - بداية التشغيل وشرح البوت

/help - المساعدة

/about - معلومات عن البوت

/scan <رابط> - فحص رابط محدد

/stats - عرض إحصائيات المستخدم

/export - تصدير تقرير المستخدم

/clear - مسح التقرير

إرسال أي رابط مباشر لفحصه تلقائيًا

------------------------------------------------------------------
ملاحظات

تأكد من عدم رفع ملف .env إلى GitHub.

جميع السجلات يتم حفظها في ملفات logs_<user_id>.txt.

هذا البوت يستخدم Telegram Bot API و VirusTotal API لفحص الروابط.

--------------------------------------------------------------------
نصائح إضافية لاحتراف المشروع

استخدام مجلد logs/ لحفظ الملفات بدل وضعها في مجلد الجذر.

تحديث README دائمًا إذا أضفت ميزات جديدة.

على Render أو أي سيرفر، ضع .env مباشرة على السيرفر بدل رفعه للمستودع.

إضافة ملف LICENSE (MIT أو Apache) لتوضيح حقوق الاستخدام.
