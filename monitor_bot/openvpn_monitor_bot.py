# -*- coding: utf-8 -*-
import os
import subprocess
from datetime import date, datetime
import glob
from OpenSSL import crypto

def get_cert_expiry_info():
    cert_dir = "/etc/openvpn/easy-rsa/pki/issued"
    cert_files = glob.glob(f"{cert_dir}/*.crt")
    result = []
    for cert_file in cert_files:
        client_name = os.path.basename(cert_file).replace(".crt", "")
        with open(cert_file, "rb") as f:
            cert_data = f.read()
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
            not_after = cert.get_notAfter().decode("ascii")
            expiry_date = datetime.strptime(not_after, "%Y%m%d%H%M%SZ")
            days_left = (expiry_date - datetime.utcnow()).days
            result.append((client_name, days_left, expiry_date))
    return result
import pytz
from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
)
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters
)

from config import TOKEN, ADMIN_ID

KEYS_DIR = "/root"
OPENVPN_DIR = "/etc/openvpn"
EASYRSA_DIR = "/etc/openvpn/easy-rsa"
IPTABLES_DIR = "/etc/iptables"
BACKUP_DIR = "/root"
STATUS_LOG = "/var/log/openvpn/status.log"
CCD_DIR = "/etc/openvpn/ccd"
NOTIFY_FILE = "/root/monitor_bot/notify.flag"
TM_TZ = pytz.timezone("Asia/Ashgabat")
MGMT_SOCKET = "/var/run/openvpn.sock"

clients_last_online = set()  # Для уведомлений

# === Новый блок: генерация .ovpn ===
def generate_ovpn_for_client(
    client_name,
    output_dir=KEYS_DIR,
    template_path=f"{OPENVPN_DIR}/client-template.txt",
    ca_path=f"{EASYRSA_DIR}/pki/ca.crt",
    cert_path=None,
    key_path=None,
    tls_crypt_path=f"{OPENVPN_DIR}/tls-crypt.key",
    tls_auth_path=f"{OPENVPN_DIR}/tls-auth.key",
    server_conf_path=f"{OPENVPN_DIR}/server.conf"
):
    if cert_path is None:
        cert_path = f"{EASYRSA_DIR}/pki/issued/{client_name}.crt"
    if key_path is None:
        key_path = f"{EASYRSA_DIR}/pki/private/{client_name}.key"

    ovpn_file = os.path.join(output_dir, f"{client_name}.ovpn")

    # Determine TLS_SIG (1=tls-crypt, 2=tls-auth)
    TLS_SIG = None
    if os.path.exists(server_conf_path):
        with open(server_conf_path, "r") as f:
            conf = f.read()
            if "tls-crypt" in conf:
                TLS_SIG = 1
            elif "tls-auth" in conf:
                TLS_SIG = 2

    # Read all parts
    with open(template_path, "r") as f:
        template_content = f.read()
    with open(ca_path, "r") as f:
        ca_content = f.read()
    with open(cert_path, "r") as f:
        cert_content = f.read()
    with open(key_path, "r") as f:
        key_content = f.read()

    ovpn_content = template_content + "\n"
    ovpn_content += "<ca>\n" + ca_content + "\n</ca>\n"
    ovpn_content += "<cert>\n" + cert_content + "\n</cert>\n"
    ovpn_content += "<key>\n" + key_content + "\n</key>\n"

    if TLS_SIG == 1 and os.path.exists(tls_crypt_path):
        with open(tls_crypt_path, "r") as f:
            tls_crypt_content = f.read()
        ovpn_content += "<tls-crypt>\n" + tls_crypt_content + "\n</tls-crypt>\n"
    elif TLS_SIG == 2 and os.path.exists(tls_auth_path):
        ovpn_content += "key-direction 1\n"
        with open(tls_auth_path, "r") as f:
            tls_auth_content = f.read()
        ovpn_content += "<tls-auth>\n" + tls_auth_content + "\n</tls-auth>\n"

    with open(ovpn_file, "w") as f:
        f.write(ovpn_content)
    return ovpn_file
# ==== Конец нового блока ====

# ... (оставь все остальные функции без изменений) ...

# === Измени только обработчик создания ключа ===
async def create_key_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Этап: ждём имя
    if context.user_data.get('await_key_name'):
        key_name = update.message.text.strip()
        ovpn_file = os.path.join(KEYS_DIR, f"{key_name}.ovpn")
        if os.path.exists(ovpn_file):
            await update.message.reply_text(
                f"Клиент с именем <b>{key_name}</b> уже существует! Введите другое имя.",
                parse_mode="HTML"
            )
            return
        context.user_data['new_key_name'] = key_name
        context.user_data['await_key_name'] = False
        context.user_data['await_key_expiry'] = True
        await update.message.reply_text(
            "Введите срок действия ключа в днях (по умолчанию 825):"
        )
        return

    # Этап: ждём срок
    if context.user_data.get('await_key_expiry'):
        try:
            days = int(update.message.text.strip())
        except:
            days = 825
        context.user_data['new_key_expiry'] = days
        context.user_data['await_key_expiry'] = False

        key_name = context.user_data['new_key_name']

        # Генерируем сертификат и ключ через EasyRSA
        try:
            subprocess.run(
                f"EASYRSA_CERT_EXPIRE={days} {EASYRSA_DIR}/easyrsa --batch build-client-full {key_name} nopass",
                shell=True, check=True, cwd=EASYRSA_DIR
            )
        except subprocess.CalledProcessError as e:
            await update.message.reply_text(
                f"Ошибка генерации сертификата: {e}", parse_mode="HTML"
            )
            context.user_data.pop('new_key_name', None)
            context.user_data.pop('new_key_expiry', None)
            return

        # Генерируем .ovpn
        ovpn_path = generate_ovpn_for_client(key_name)

        await update.message.reply_text(
            f"Клиент <b>{key_name}</b> успешно создан!\nСрок действия: {days} дней.\nСохраняется в: {ovpn_path}",
            parse_mode="HTML"
        )

        # Отправляем .ovpn
        with open(ovpn_path, "rb") as f:
            await context.bot.send_document(
                chat_id=update.effective_chat.id,
                document=InputFile(f),
                filename=f"{key_name}.ovpn"
            )

        context.user_data.pop('new_key_name', None)
        context.user_data.pop('new_key_expiry', None)
        return

# ... (оставь остальные обработчики и main() как есть) ...

def parse_openvpn_status(status_path=STATUS_LOG):
    clients = []
    online_names = set()
    tunnel_ips = {}
    try:
        with open(status_path, "r") as f:
            lines = f.readlines()
        client_list_section = False
        routing_table_section = False
        for line in lines:
            line = line.strip()
            if line.startswith("OpenVPN CLIENT LIST"):
                client_list_section = True
                continue
            if client_list_section and line.startswith("Common Name,Real Address"):
                continue
            if client_list_section and not line:
                client_list_section = False
                continue
            if client_list_section and "," in line:
                parts = line.split(",")
                if len(parts) >= 5:
                    common_name = parts[0]
                    real_addr = parts[1]
                    bytes_recv = parts[2]
                    bytes_sent = parts[3]
                    connected_since = parts[4]
                    clients.append({
                        "name": common_name,
                        "ip": real_addr.split(":")[0],
                        "port": real_addr.split(":")[1] if ":" in real_addr else "",
                        "bytes_recv": bytes_recv,
                        "bytes_sent": bytes_sent,
                        "connected_since": connected_since,
                    })
            if line.startswith("ROUTING TABLE"):
                routing_table_section = True
                continue
            if routing_table_section and line.startswith("Virtual Address,Common Name"):
                continue
            if routing_table_section and not line:
                routing_table_section = False
                continue
            if routing_table_section and "," in line:
                parts = line.split(",")
                if len(parts) >= 2:
                    tunnel_ip = parts[0]
                    cname = parts[1]
                    tunnel_ips[cname] = tunnel_ip
                    online_names.add(cname)
    except Exception as e:
        print(f"Ошибка чтения status.log: {e}")
    return clients, online_names, tunnel_ips

def bytes_to_mb(b):
    try:
        return f"{int(b)/1024/1024:.2f} MB"
    except:
        return "0 MB"

def split_message(text, max_length=4000):
    lines = text.split('\n')
    messages = []
    current = ""
    for line in lines:
        if len(current) + len(line) + 1 < max_length:
            current += line + '\n'
        else:
            messages.append(current)
            current = line + '\n'
    if current:
        messages.append(current)
    return messages

def format_tm_time(dt_str):
    try:
        dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        dt = pytz.utc.localize(dt).astimezone(TM_TZ)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return dt_str

def get_main_keyboard():
    keyboard = [
        [InlineKeyboardButton("🔄 Обновить список", callback_data='refresh')],
        [InlineKeyboardButton("📊 Статистика", callback_data='stats'),
         InlineKeyboardButton("🟢 Онлайн клиенты", callback_data='online')],
        [InlineKeyboardButton("⏳ Сроки ключей", callback_data='keys_expiry')],
        [InlineKeyboardButton("✅ Включить клиента", callback_data='enable')],
        [InlineKeyboardButton("⚠️ Отключить клиента", callback_data='disable')],
        [InlineKeyboardButton("📜 Просмотр лога", callback_data='log')],
        [InlineKeyboardButton("📤 Отправить ключи", callback_data='send_keys')],
        [InlineKeyboardButton("🗑️ Удалить ключ", callback_data='delete_key')],
        [InlineKeyboardButton("➕ Создать ключ", callback_data='create_key')],
        [InlineKeyboardButton("📦 Бэкап OpenVPN", callback_data='backup')],
        [InlineKeyboardButton("🔄 Восстановить бэкап", callback_data='restore')],
        [InlineKeyboardButton("🔔 Уведомления", callback_data='notify')],
        [InlineKeyboardButton("❓ Помощь", callback_data='help')],
        [InlineKeyboardButton("🏠 В главное меню", callback_data='home')],
    ]
    return InlineKeyboardMarkup(keyboard)

def get_keys_keyboard(keys):
    keyboard = []
    for i, fname in enumerate(keys, 1):
        keyboard.append([InlineKeyboardButton(f"{i}. {fname}", callback_data=f"key_{i}")])
    keyboard.append([InlineKeyboardButton("⬅️ Назад", callback_data='home')])
    return InlineKeyboardMarkup(keyboard)

def get_delete_keys_keyboard(keys):
    keyboard = []
    for i, fname in enumerate(keys, 1):
        keyboard.append([InlineKeyboardButton(f"{i}. {fname}", callback_data=f"delete_{fname}")])
    keyboard.append([InlineKeyboardButton("⬅️ Назад", callback_data='home')])
    return InlineKeyboardMarkup(keyboard)

def get_confirm_delete_keyboard(fname):
    keyboard = [
        [InlineKeyboardButton("✅ Да, удалить", callback_data=f"confirm_delete_{fname}")],
        [InlineKeyboardButton("❌ Нет, отмена", callback_data="cancel_delete")],
    ]
    return InlineKeyboardMarkup(keyboard)

HELP_TEXT = """
<b>Доступные команды:</b>
🔄 Обновить список — показать всех клиентов
📊 Статистика — статус всех ключей (зелёный: онлайн, красный: оффлайн)
🟢 Онлайн клиенты — только активные
✅ Включить клиента — разблокировать ключ (через CCD)
⚠️ Отключить клиента — заблокировать (через CCD) и отключить сессию
📜 Просмотр лога — последние строки status.log
📤 Отправить ключи — выбрать и получить .ovpn файл
🗑️ Удалить ключ — выбрать и полностью удалить ключ
📦 Бэкап OpenVPN — архивировать настройки и ключи
🔄 Восстановить бэкап — восстановить из архива
🔔 Уведомления — включить/выключить оповещения
🏠 В главное меню — перейти к основному меню
"""

def format_all_keys_with_status(keys_dir=KEYS_DIR, clients_online=set()):
    files = [f for f in os.listdir(keys_dir) if f.endswith(".ovpn")]
    result = "<b>Статус всех ключей:</b>\n\n"
    for f in sorted(files):
        key_name = f[:-5]
        if key_name in clients_online and not is_client_ccd_disabled(key_name):
            result += f"🟢 <b>{key_name}</b>\n"
        elif is_client_ccd_disabled(key_name):
            result += f"⛔ <b>{key_name}</b> (заблокирован через CCD)\n"
        else:
            result += f"🔴 <b>{key_name}</b>\n"
    if not files:
        result += "Нет ключей."
    return result

def format_clients(clients, online_names, tunnel_ips):
    result = "<b>Список клиентов (только сессии):</b>\n\n"
    for c in clients:
        if is_client_ccd_disabled(c['name']):
            status_circle = "⛔"
        else:
            status_circle = "🟢" if c['name'] in online_names else "🔴"
        tunnel_ip = tunnel_ips.get(c['name'], 'нет данных')
        result += (
            f"{status_circle} <b>{c['name']}</b>\n"
            f"🌐 <code>{c.get('ip', 'нет данных')}</code>\n"
            f"🛡️ <b>Tunnel IP:</b> <code>{tunnel_ip}</code>\n"
            f"🔌 <b>Порт:</b> <code>{c.get('port', '')}</code>\n"
            f"📥 <b>Получено:</b> <code>{bytes_to_mb(c.get('bytes_recv', 0))}</code>\n"
            f"📤 <b>Отправлено:</b> <code>{bytes_to_mb(c.get('bytes_sent', 0))}</code>\n"
            f"🕒 <b>Сессия с:</b> <code>{format_tm_time(c.get('connected_since', ''))}</code>\n"
            + "-"*15 + "\n"
        )
    if not clients:
        result += "Нет клиентов."
    return result

def format_online_clients(clients, online_names, tunnel_ips):
    result = "<b>Онлайн клиенты:</b>\n\n"
    count = 0
    for c in clients:
        if c['name'] in online_names and not is_client_ccd_disabled(c['name']):
            count += 1
            tunnel_ip = tunnel_ips.get(c['name'], 'нет данных')
            result += (
                f"🟢 <b>{c['name']}</b>\n"
                f"🌐 <code>{c.get('ip', 'нет данных')}</code>\n"
                f"🛡️ <b>Tunnel IP:</b> <code>{tunnel_ip}</code>\n"
                f"🔌 <b>Порт:</b> <code>{c.get('port', '')}</code>\n"
                f"📥 <b>Получено:</b> <code>{bytes_to_mb(c.get('bytes_recv', 0))}</code>\n"
                f"📤 <b>Отправлено:</b> <code>{bytes_to_mb(c.get('bytes_sent', 0))}</code>\n"
                f"🕒 <b>Сессия с:</b> <code>{format_tm_time(c.get('connected_since', ''))}</code>\n"
                + "-"*15 + "\n"
            )
    if count == 0:
        result += "Нет активных клиентов."
    return result

def get_ovpn_files():
    return [f for f in os.listdir(KEYS_DIR) if f.endswith(".ovpn")]

def is_client_ccd_disabled(client_name):
    ccd_path = os.path.join(CCD_DIR, client_name)
    if not os.path.exists(ccd_path):
        return False
    try:
        with open(ccd_path, "r") as f:
            content = f.read().strip()
        return "disable" in content
    except Exception:
        return False

def block_client_ccd(client_name):
    ccd_path = os.path.join(CCD_DIR, client_name)
    with open(ccd_path, "w") as f:
        f.write("disable\n")

def unblock_client_ccd(client_name):
    ccd_path = os.path.join(CCD_DIR, client_name)
    if os.path.exists(ccd_path):
        os.remove(ccd_path)

def kill_openvpn_session(client_name):
    if os.path.exists(MGMT_SOCKET):
        try:
            subprocess.run(f'echo "kill {client_name}" | nc -U {MGMT_SOCKET}', shell=True)
            return True
        except Exception as e:
            print(f"Ошибка отключения клиента через management socket: {e}")
    return False

def show_enable_keyboard(all_keys):
    result = []
    for fname in sorted(all_keys):
        cname = fname[:-5]
        if is_client_ccd_disabled(cname):
            result.append([InlineKeyboardButton(f"✅ Включить {cname}", callback_data=f"enable_{cname}")])
    if not result:
        result.append([InlineKeyboardButton("Нет заблокированных клиентов", callback_data='home')])
    result.append([InlineKeyboardButton("⬅️ Назад", callback_data='home')])
    return InlineKeyboardMarkup(result)

def show_disable_keyboard(all_keys):
    result = []
    for fname in sorted(all_keys):
        cname = fname[:-5]
        if not is_client_ccd_disabled(cname):
            result.append([InlineKeyboardButton(f"⚠️ Отключить {cname}", callback_data=f"disable_{cname}")])
    if not result:
        result.append([InlineKeyboardButton("Нет клиентов для отключения", callback_data='home')])
    result.append([InlineKeyboardButton("⬅️ Назад", callback_data='home')])
    return InlineKeyboardMarkup(result)

async def enable_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    all_keys = get_ovpn_files()
    await query.edit_message_text(
        "Выбери клиента для включения (разблокировки через CCD):",
        reply_markup=show_enable_keyboard(all_keys)
    )

async def disable_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    all_keys = get_ovpn_files()
    await query.edit_message_text(
        "Выбери клиента для отключения (блокировки через CCD):",
        reply_markup=show_disable_keyboard(all_keys)
    )

async def enable_client_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    cname = query.data.split('_', 1)[1]
    unblock_client_ccd(cname)
    await query.edit_message_text(f"Клиент <b>{cname}</b> включён (разблокирован через CCD).", parse_mode="HTML", reply_markup=get_main_keyboard())

async def disable_client_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    cname = query.data.split('_', 1)[1]
    block_client_ccd(cname)
    killed = kill_openvpn_session(cname)
    msg = f"Клиент <b>{cname}</b> отключён (заблокирован через CCD)."
    if killed:
        msg += "\nСессия принудительно завершена."
    else:
        msg += "\nЕсли сессия была активна — она завершится при переподключении."
    await query.edit_message_text(msg, parse_mode="HTML", reply_markup=get_main_keyboard())

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Доступ запрещён.")
        return
    await update.message.reply_text("Добро пожаловать в VPN бот!", reply_markup=get_main_keyboard())

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Доступ запрещён.")
        return
    await update.message.reply_text(HELP_TEXT, parse_mode="HTML", reply_markup=get_main_keyboard())

async def clients_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Доступ запрещён.")
        return
    clients, online_names, tunnel_ips = parse_openvpn_status()
    msgs = split_message(format_clients(clients, online_names, tunnel_ips))
    for i, msg in enumerate(msgs):
        if i == 0:
            await update.message.reply_text(msg, parse_mode="HTML", reply_markup=get_main_keyboard())
        else:
            await update.message.reply_text(msg, parse_mode="HTML")
            
async def view_keys_expiry_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keys_info = get_cert_expiry_info()
    text = "<b>Сроки действия клиентских ключей:</b>\n"
    if not keys_info:
        text += "Нет активных ключей."
    else:
        for client_name, days_left, expiry_date in sorted(keys_info):
            if days_left < 0:
                status = "❌ истёк"
            elif days_left < 7:
                status = f"⚠️ {days_left} дней"
            else:
                status = f"{days_left} дней"
            text += f"• <b>{client_name}</b>: {status} (до {expiry_date.strftime('%Y-%m-%d')})\n"

    if update.callback_query:
        await update.callback_query.edit_message_text(text, parse_mode="HTML", reply_markup=get_main_keyboard())
    else:
        await update.message.reply_text(text, parse_mode="HTML", reply_markup=get_main_keyboard())

async def online_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Доступ запрещён.")
        return
    clients, online_names, tunnel_ips = parse_openvpn_status()
    msgs = split_message(format_online_clients(clients, online_names, tunnel_ips))
    for i, msg in enumerate(msgs):
        if i == 0:
            await update.message.reply_text(msg, parse_mode="HTML", reply_markup=get_main_keyboard())
        else:
            await update.message.reply_text(msg, parse_mode="HTML")

async def send_keys_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Доступ запрещён.")
        return
    keys = get_ovpn_files()
    await update.message.reply_text("Выберите номер ключа для отправки:", reply_markup=get_keys_keyboard(keys))

async def send_ovpn_file(update: Update, context: ContextTypes.DEFAULT_TYPE, filename):
    file_path = os.path.join(KEYS_DIR, filename)
    if not os.path.exists(file_path):
        if update.callback_query:
            await update.callback_query.edit_message_text(
                f"Файл {filename} не найден в {KEYS_DIR}!", reply_markup=get_main_keyboard()
            )
        else:
            await update.message.reply_text(
                f"Файл {filename} не найден в {KEYS_DIR}!", reply_markup=get_main_keyboard()
            )
        return
    with open(file_path, "rb") as f:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=InputFile(f),
            filename=filename
        )

async def delete_key_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keys = get_ovpn_files()
    if not keys:
        await update.callback_query.edit_message_text("Нет ключей для удаления.", reply_markup=get_main_keyboard())
        return
    await update.callback_query.edit_message_text(
        "Выберите ключ для удаления:",
        reply_markup=get_delete_keys_keyboard(keys)
    )
    
async def ask_key_name(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.callback_query.edit_message_text(
        "Введите имя для нового клиента (например, vpnuser1):"
    )
    context.user_data['await_key_name'] = True

async def delete_key_select_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    fname = query.data.split('_', 1)[1]
    await query.edit_message_text(
        f"Вы уверены, что хотите удалить ключ <b>{fname}</b>?\nДействие необратимо!",
        parse_mode="HTML",
        reply_markup=get_confirm_delete_keyboard(fname)
    )

async def delete_key_confirm_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    fname = query.data.split('_', 2)[2]
    client_name = fname[:-5] if fname.endswith(".ovpn") else fname

    try:
        # 1. Завершить сессию клиента (management socket)
        kill_openvpn_session(client_name)

        # 2. Revoke сертификат
        revoke_cmd = f"cd {EASYRSA_DIR} && ./easyrsa --batch revoke {client_name}"
        subprocess.run(revoke_cmd, shell=True, check=True)

        # 3. Сгенерировать новый CRL
        subprocess.run(f"cd {EASYRSA_DIR} && EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl", shell=True, check=True)

        # 4. Скопировать CRL в openvpn
        crl_src = f"{EASYRSA_DIR}/pki/crl.pem"
        crl_dst = "/etc/openvpn/crl.pem"
        if os.path.exists(crl_src):
            subprocess.run(f"cp {crl_src} {crl_dst}", shell=True, check=True)
            os.chmod(crl_dst, 0o644)

        # 5. Удалить все файлы клиента
        ovpn_path = os.path.join(KEYS_DIR, fname)
        if os.path.exists(ovpn_path):
            os.remove(ovpn_path)
        crt_path = f"{EASYRSA_DIR}/pki/issued/{client_name}.crt"
        if os.path.exists(crt_path):
            os.remove(crt_path)
        key_path = f"{EASYRSA_DIR}/pki/private/{client_name}.key"
        if os.path.exists(key_path):
            os.remove(key_path)
        req_path = f"{EASYRSA_DIR}/pki/reqs/{client_name}.req"
        if os.path.exists(req_path):
            os.remove(req_path)
        ccd_path = os.path.join(CCD_DIR, client_name)
        if os.path.exists(ccd_path):
            os.remove(ccd_path)

    except Exception as e:
        await query.edit_message_text(f"Ошибка удаления ключа: {e}", reply_markup=get_main_keyboard())
        return

    await query.edit_message_text(f"Ключ <b>{fname}</b> удалён полностью!", parse_mode="HTML", reply_markup=get_main_keyboard())

async def delete_key_cancel_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.edit_message_text("Удаление отменено.", reply_markup=get_main_keyboard())

def generate_ovpn_for_client(
    client_name,
    output_dir="/root",
    template_path="/etc/openvpn/client-template.txt",
    ca_path="/etc/openvpn/easy-rsa/pki/ca.crt",
    cert_path=None,
    key_path=None,
    tls_crypt_path="/etc/openvpn/tls-crypt.key",
    tls_auth_path="/etc/openvpn/tls-auth.key",
    server_conf_path="/etc/openvpn/server.conf"
):
    if cert_path is None:
        cert_path = f"/etc/openvpn/easy-rsa/pki/issued/{client_name}.crt"
    if key_path is None:
        key_path = f"/etc/openvpn/easy-rsa/pki/private/{client_name}.key"

    ovpn_file = os.path.join(output_dir, f"{client_name}.ovpn")

    TLS_SIG = None
    if os.path.exists(server_conf_path):
        with open(server_conf_path, "r") as f:
            conf = f.read()
            if "tls-crypt" in conf:
                TLS_SIG = 1
            elif "tls-auth" in conf:
                TLS_SIG = 2

    with open(template_path, "r") as f:
        template_content = f.read()
    with open(ca_path, "r") as f:
        ca_content = f.read()
    with open(cert_path, "r") as f:
        cert_content = f.read()
    with open(key_path, "r") as f:
        key_content = f.read()

    ovpn_content = template_content + "\n"
    ovpn_content += "<ca>\n" + ca_content + "\n</ca>\n"
    ovpn_content += "<cert>\n" + cert_content + "\n</cert>\n"
    ovpn_content += "<key>\n" + key_content + "\n</key>\n"

    if TLS_SIG == 1 and os.path.exists(tls_crypt_path):
        with open(tls_crypt_path, "r") as f:
            tls_crypt_content = f.read()
        ovpn_content += "<tls-crypt>\n" + tls_crypt_content + "\n</tls-crypt>\n"
    elif TLS_SIG == 2 and os.path.exists(tls_auth_path):
        ovpn_content += "key-direction 1\n"
        with open(tls_auth_path, "r") as f:
            tls_auth_content = f.read()
        ovpn_content += "<tls-auth>\n" + tls_auth_content + "\n</tls-auth>\n"

    with open(ovpn_file, "w") as f:
        f.write(ovpn_content)
    return ovpn_file

async def create_key_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Этап: ждём имя
    if context.user_data.get('await_key_name'):
        key_name = update.message.text.strip()
        ovpn_file = os.path.join(KEYS_DIR, f"{key_name}.ovpn")
        if os.path.exists(ovpn_file):
            await update.message.reply_text(
                f"Клиент с именем <b>{key_name}</b> уже существует! Введите другое имя.",
                parse_mode="HTML"
            )
            return
        context.user_data['new_key_name'] = key_name
        context.user_data['await_key_name'] = False
        context.user_data['await_key_expiry'] = True
        await update.message.reply_text(
            "Введите срок действия ключа в днях (по умолчанию 825):"
        )
        return

    # Этап: ждём срок
    if context.user_data.get('await_key_expiry'):
        try:
            days = int(update.message.text.strip())
        except:
            days = 825
        context.user_data['new_key_expiry'] = days
        context.user_data['await_key_expiry'] = False

        key_name = context.user_data['new_key_name']
        cert_path = f"{EASYRSA_DIR}/pki/issued/{key_name}.crt"
        key_path = f"{EASYRSA_DIR}/pki/private/{key_name}.key"

        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            try:
                subprocess.run(
                    f"EASYRSA_CERT_EXPIRE={days} {EASYRSA_DIR}/easyrsa --batch build-client-full {key_name} nopass",
                    shell=True, check=True, cwd=EASYRSA_DIR
                )
            except subprocess.CalledProcessError as e:
                await update.message.reply_text(
                    f"Ошибка генерации сертификата: {e}", parse_mode="HTML"
                )
                context.user_data.pop('new_key_name', None)
                context.user_data.pop('new_key_expiry', None)
                return

        ovpn_path = generate_ovpn_for_client(key_name)

        await update.message.reply_text(
            f"Клиент <b>{key_name}</b> успешно создан!\nСрок действия: {days} дней.\nСохраняется в: {ovpn_path}",
            parse_mode="HTML"
        )

        with open(ovpn_path, "rb") as f:
            await context.bot.send_document(
                chat_id=update.effective_chat.id,
                document=InputFile(f),
                filename=f"{key_name}.ovpn"
            )

        context.user_data.pop('new_key_name', None)
        context.user_data.pop('new_key_expiry', None)
        return

async def restore_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.callback_query.answer()
    await update.callback_query.edit_message_text(
        "Пожалуйста, отправьте архив с бэкапом (.tar.gz) в этот чат."
    )
    context.user_data['restore_wait_file'] = True

async def document_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("Доступ запрещён.")
        return
    if context.user_data.get('restore_wait_file'):
        file = update.message.document
        if file and (
            file.mime_type in ['application/gzip', 'application/x-gzip', 'application/x-tar', 'application/octet-stream']
            or file.file_name.endswith('.tar.gz') or file.file_name.endswith('.tgz') or file.file_name.endswith('.tar')
        ):
            file_id = file.file_id
            file_name = file.file_name
            new_path = f"/root/{file_name}"
            new_file = await context.bot.get_file(file_id)
            await new_file.download_to_drive(new_path)
            context.user_data['restore_wait_file'] = False

            keyboard = InlineKeyboardMarkup([
                [InlineKeyboardButton("✅ Да, восстановить", callback_data='restore_confirm')],
                [InlineKeyboardButton("❌ Нет, отменить", callback_data='restore_cancel')],
            ])
            await update.message.reply_text(
                f"Бэкап получен: <code>{file_name}</code>\nВосстановить этот архив?",
                parse_mode="HTML",
                reply_markup=keyboard
            )
        else:
            await update.message.reply_text("Пожалуйста, отправьте архив в формате .tar.gz")
    else:
        await update.message.reply_text("Для восстановления сначала нажмите 'Восстановить бэкап'.")

async def restore_confirm_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    file_path = context.user_data.get('restore_file_path')
    if file_path and os.path.exists(file_path):
        # Распаковываем архив в корень /
        subprocess.run(f"tar -xzvf {file_path} -C /", shell=True)
        await update.callback_query.answer("Восстановление завершено!")
        await update.callback_query.edit_message_text("✅ Архив успешно восстановлен! Все файлы восстановлены.", reply_markup=get_main_keyboard())
        context.user_data['restore_file_path'] = None
    else:
        await update.callback_query.answer("Файл для восстановления не найден!", show_alert=True)
        await update.callback_query.edit_message_text("❌ Ошибка: файл не найден или не был отправлен.", reply_markup=get_main_keyboard())

async def restore_cancel_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data['restore_file_path'] = None
    await update.callback_query.answer("Отменено.")
    await update.callback_query.edit_message_text("Восстановление отменено.", reply_markup=get_main_keyboard())

def get_status_log_tail(n=40):
    try:
        with open(STATUS_LOG, "r") as f:
            lines = f.readlines()
        return "".join(lines[-n:])
    except Exception as e:
        return f"Ошибка чтения status.log: {e}"

async def log_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    log_text = get_status_log_tail()
    msgs = split_message(f"<b>Последние строки status.log:</b>\n\n<pre>{log_text}</pre>", 4000)
    await query.edit_message_text(msgs[0], parse_mode="HTML", reply_markup=get_main_keyboard())
    for msg in msgs[1:]:
        await context.bot.send_message(chat_id=update.effective_chat.id, text=msg, parse_mode="HTML")

def is_notify_enabled():
    return os.path.exists(NOTIFY_FILE)

def set_notify(flag):
    if flag:
        with open(NOTIFY_FILE, "w") as f:
            f.write("on")
    else:
        if os.path.exists(NOTIFY_FILE):
            os.remove(NOTIFY_FILE)

async def notify_toggle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    enabled = is_notify_enabled()
    set_notify(not enabled)
    if not enabled:
        await query.edit_message_text("✅ Уведомления о новых подключениях ВКЛЮЧЕНЫ.", reply_markup=get_main_keyboard())
    else:
        await query.edit_message_text("🚫 Уведомления о новых подключениях ВЫКЛЮЧЕНЫ.", reply_markup=get_main_keyboard())

async def check_new_connections(app: Application):
    global clients_last_online
    import asyncio
    while True:
        clients, online_names, tunnel_ips = parse_openvpn_status()
        if is_notify_enabled():
            new_clients = online_names - clients_last_online
            if new_clients:
                msg = "<b>Новые подключения:</b>\n\n"
                for cname in new_clients:
                    tunnel_ip = tunnel_ips.get(cname, 'нет данных')
                    now_tm = datetime.now(pytz.utc).astimezone(TM_TZ).strftime("%Y-%m-%d %H:%M:%S")
                    msg += f"🟢 <b>{cname}</b> (<code>{tunnel_ip}</code>) — {now_tm}\n"
                await app.bot.send_message(chat_id=ADMIN_ID, text=msg, parse_mode="HTML")
        clients_last_online = set(online_names)
        await asyncio.sleep(10)

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if query.from_user.id != ADMIN_ID:
        await query.answer("Доступ запрещён.", show_alert=True)
        return
    await query.answer()
    data = query.data

    if data == 'refresh':
        clients, online_names, tunnel_ips = parse_openvpn_status()
        msgs = split_message(format_clients(clients, online_names, tunnel_ips))
        await query.edit_message_text(msgs[0], parse_mode="HTML", reply_markup=get_main_keyboard())
        for msg in msgs[1:]:
            await context.bot.send_message(chat_id=update.effective_chat.id, text=msg, parse_mode="HTML")
    elif data == 'stats':
        clients, online_names, tunnel_ips = parse_openvpn_status()
        message = format_all_keys_with_status(KEYS_DIR, online_names)
        msgs = split_message(message)
        await query.edit_message_text(msgs[0], parse_mode="HTML", reply_markup=get_main_keyboard())
        for msg in msgs[1:]:
            await context.bot.send_message(chat_id=update.effective_chat.id, text=msg, parse_mode="HTML")
    elif data == 'online':
        clients, online_names, tunnel_ips = parse_openvpn_status()
        msgs = split_message(format_online_clients(clients, online_names, tunnel_ips))
        await query.edit_message_text(msgs[0], parse_mode="HTML", reply_markup=get_main_keyboard())
        for msg in msgs[1:]:
            await context.bot.send_message(chat_id=update.effective_chat.id, text=msg, parse_mode="HTML")
    elif data == 'keys_expiry':
            await view_keys_expiry_handler(update, context)
    elif data == 'help':
        msgs = split_message(HELP_TEXT)
        await query.edit_message_text(msgs[0], parse_mode="HTML", reply_markup=get_main_keyboard())
        for msg in msgs[1:]:
            await context.bot.send_message(chat_id=update.effective_chat.id, text=msg, parse_mode="HTML")
    elif data == 'restore_confirm':
        await restore_confirm_handler(update, context)
    elif data == 'restore_cancel':
        await restore_cancel_handler(update, context)        
    elif data == 'send_keys':
        keys = get_ovpn_files()
        await query.edit_message_text(
            "Выберите номер ключа для отправки:",
            reply_markup=get_keys_keyboard(keys)
        )
    elif data.startswith('key_'):
        idx = int(data.split('_')[1]) - 1
        keys = get_ovpn_files()
        if 0 <= idx < len(keys):
            await send_ovpn_file(update, context, keys[idx])
    elif data == 'delete_key':
        await delete_key_request(update, context)
    elif data.startswith('delete_'):
        await delete_key_select_handler(update, context)
    elif data.startswith('confirm_delete_'):
        await delete_key_confirm_handler(update, context)
    elif data == 'cancel_delete':
        await delete_key_cancel_handler(update, context)
    elif data == 'create_key':
        await ask_key_name(update, context)
    elif data == 'backup':
        await send_backup(update, context)
    elif data == 'restore':
        await restore_request(update, context)
    elif data == 'home':
        await query.edit_message_text(
            "Добро пожаловать в VPN бот!",
            reply_markup=get_main_keyboard()
        )
    elif data == 'enable':
        await enable_request(update, context)
    elif data.startswith('enable_'):
        await enable_client_handler(update, context)
    elif data == 'disable':
        await disable_request(update, context)
    elif data.startswith('disable_'):
        await disable_client_handler(update, context)
    elif data == 'log':
        await log_request(update, context)
    elif data == 'notify':
        await notify_toggle(update, context)
    else:
        await query.edit_message_text("Команда не реализована.", reply_markup=get_main_keyboard())

def create_backup():
    backup_file = f"{BACKUP_DIR}/vpn_backup_{date.today().strftime('%Y%m%d')}.tar.gz"
    ovpn_files = [os.path.join(KEYS_DIR, f) for f in os.listdir(KEYS_DIR) if f.endswith(".ovpn")]
    files_to_backup = ovpn_files + [OPENVPN_DIR, IPTABLES_DIR]
    cmd = ["tar", "-czvf", backup_file] + files_to_backup
    subprocess.run(cmd)
    return backup_file

async def send_backup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    backup_file = create_backup()
    with open(backup_file, "rb") as f:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=InputFile(f),
            filename=os.path.basename(backup_file)
        )

def main():
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("clients", clients_command))
    app.add_handler(CommandHandler("online", online_command))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(CallbackQueryHandler(restore_confirm_handler, pattern='^restore_confirm$'))
    app.add_handler(CallbackQueryHandler(restore_cancel_handler, pattern='^restore_cancel$'))
    app.add_handler(MessageHandler(filters.Document.ALL, document_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, create_key_handler))
    import asyncio
    loop = asyncio.get_event_loop()
    loop.create_task(check_new_connections(app))
    app.run_polling()

if __name__ == '__main__':
    main()
