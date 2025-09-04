import os
import logging
import requests
import re
from datetime import datetime
from dotenv import load_dotenv
from telegram import Update, InputFile, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, CallbackQueryHandler
import matplotlib.pyplot as plt  # 📊 لإضافة الرسم

# تحميل القيم من ملف .env
load_dotenv()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_TOKEN")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# إعداد اللوج
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

# ======= دوال مساعدة =======
def get_user_log_file(user_id):
    return f"logs_{user_id}.txt"

def save_log(user_id, url, malicious, harmless):
    log_file = get_user_log_file(user_id)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(
            f"[{datetime.now()}] URL: {url}, ضار={malicious}, آمن={harmless}\n"
        )

def get_stats(user_id):
    log_file = get_user_log_file(user_id)
    if not os.path.exists(log_file):
        return {"total": 0, "malicious": 0, "harmless": 0}
    malicious = harmless = 0
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            if "ضار=" in line and "آمن=" in line:
                try:
                    m = int(line.split("ضار=")[1].split(",")[0])
                    h = int(line.split("آمن=")[1].strip())
                    malicious += m
                    harmless += h
                except:
                    pass
    return {"total": malicious + harmless, "malicious": malicious, "harmless": harmless}

# ======= أوامر البوت =======
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "👋 مرحبا بك في بوت الفحص 🔍\n\n"
        "الأوامر المتاحة:\n"
        "/scan + رابط 🔗 - فحص رابط\n"
        "/export - تصدير تقريرك\n"
        "/clear - مسح تقريرك\n"
        "/stats - عرض إحصائياتك\n"
        "/help - المساعدة\n"
        "/about - حول البوت\n\n"
        "📌 أو أرسل أي رابط مباشر ليتم فحصه ✅"
    )
    await update.message.reply_text(msg)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "ℹ️ المساعدة:\n\n"
        "1️⃣ ارسل /scan ثم الرابط\n"
        "مثال: /scan https://example.com\n\n"
        "2️⃣ استعمل /export لتصدير تقريرك\n"
        "3️⃣ استعمل /clear لمسح تقريرك\n"
        "4️⃣ استعمل /stats لعرض إحصائياتك\n\n"
        "📌 أو ببساطة أرسل أي رابط وسيتم فحصه تلقائيًا ✅"
    )
    await update.message.reply_text(msg)

async def about(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🤖 بوت فحص الروابط باستخدام VirusTotal API.")

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("⚠️ يجب إدخال رابط.\nمثال:\n/scan https://example.com")
        return
    url = context.args[0]
    await scan_link(update, url)

# ======= دالة الفحص =======
async def scan_link(update: Update, url: str):
    user_id = update.effective_user.id
    await update.message.reply_text(f"⏳ جاري فحص الرابط: {url}")

    try:
        headers = {"x-apikey": VT_API_KEY}
        data = {"url": url}
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)

        if response.status_code == 200:
            res = response.json()
            scan_id = res["data"]["id"]

            result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers).json()
            stats = result["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            harmless = stats.get("harmless", 0)

            msg = f"🔍 النتيجة:\n🔴 ضار: {malicious}\n🟢 آمن: {harmless}"

            # أزرار التحكم
            keyboard = [
                [InlineKeyboardButton("📂 تصدير تقريري", callback_data="export")],
                [InlineKeyboardButton("🗑️ مسح تقريري", callback_data="clear")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)

            await update.message.reply_text(msg, reply_markup=reply_markup)

            # حفظ في سجل المستخدم
            save_log(user_id, url, malicious, harmless)

        else:
            await update.message.reply_text("⚠️ خطأ أثناء الاتصال بـ VirusTotal.")

    except Exception as e:
        await update.message.reply_text(f"❌ خطأ: {e}")

# ======= الفحص التلقائي =======
async def auto_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    url_pattern = re.compile(r"(https?://[^\s]+|www\.[^\s]+)")
    urls = url_pattern.findall(text)
    for url in urls:
        if url.startswith("www."):
            url = "https://" + url
        await scan_link(update, url)

# ======= تصدير التقرير =======
async def export_report(user_id, chat_id, context: ContextTypes.DEFAULT_TYPE):
    log_file = get_user_log_file(user_id)
    if not os.path.exists(log_file):
        await context.bot.send_message(chat_id, "⚠️ لا يوجد تقارير لك حتى الآن.")
        return
    with open(log_file, "rb") as f:
        await context.bot.send_document(chat_id, InputFile(f), filename="scan_report.txt")

# ======= مسح التقرير =======
async def clear_report(user_id, chat_id, context: ContextTypes.DEFAULT_TYPE):
    log_file = get_user_log_file(user_id)
    if os.path.exists(log_file):
        os.remove(log_file)
        await context.bot.send_message(chat_id, "🗑️ تم مسح تقريرك بنجاح.")
    else:
        await context.bot.send_message(chat_id, "⚠️ لا يوجد تقارير لمسحها.")

# ======= عرض الإحصائيات =======
async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    s = get_stats(user_id)
    msg = (
        f"📊 إحصائياتك:\n\n"
        f"إجمالي الروابط المفحوصة: {s['total']}\n"
        f"🔴 ضارة: {s['malicious']}\n"
        f"🟢 آمنة: {s['harmless']}"
    )
    await update.message.reply_text(msg)

    # 📊 رسم بياني (Pie Chart)
    if s["total"] > 0:
        labels = ["ضارة", "آمنة"]
        values = [s["malicious"], s["harmless"]]
        colors = ["red", "green"]

        plt.figure(figsize=(4, 4))
        plt.pie(values, labels=labels, colors=colors, autopct="%1.1f%%", startangle=90)
        plt.title("نسبة الروابط")
        chart_file = f"chart_{user_id}.png"
        plt.savefig(chart_file)
        plt.close()

        with open(chart_file, "rb") as f:
            await update.message.reply_photo(InputFile(f), caption="📊 توزيع الروابط")
        os.remove(chart_file)

# ======= التعامل مع الأزرار =======
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    chat_id = query.message.chat_id

    if query.data == "export":
        await export_report(user_id, chat_id, context)
    elif query.data == "clear":
        await clear_report(user_id, chat_id, context)

# ======= تشغيل البوت =======
def main():
    if not TELEGRAM_BOT_TOKEN:
        raise ValueError("⚠️ لم يتم العثور على TELEGRAM_TOKEN")
    if not VT_API_KEY:
        raise ValueError("⚠️ لم يتم العثور على VT_API_KEY")

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("about", about))
    app.add_handler(CommandHandler("scan", scan))
    app.add_handler(CommandHandler("stats", stats))

    # الأوامر المباشرة
    app.add_handler(CommandHandler("export", lambda u, c: export_report(u.effective_user.id, u.effective_chat.id, c)))
    app.add_handler(CommandHandler("clear", lambda u, c: clear_report(u.effective_user.id, u.effective_chat.id, c)))

    # الأزرار
    app.add_handler(CallbackQueryHandler(button_handler))

    # الفحص التلقائي لأي رابط
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, auto_scan))

    logging.info("🚀 Bot is running...")
    app.run_polling()

if __name__ == "__main__":
    main()
