#!/bin/bash
set -e

# 1. Копируем install_openvpn_xormask.sh в /root (если нужно обновить — перезаписываем)
cp install_openvpn_xormask.sh /root/install_openvpn_xormask.sh
chmod +x /root/install_openvpn_xormask.sh

# 2. Запускаем его из /root
bash /root/install_openvpn_xormask.sh

# 3. Дальше как раньше...
echo "Введите Telegram BOT TOKEN (например, 123456:ABC...):"
read -r BOT_TOKEN
echo "Введите ваш Telegram ID (например, 123456789):"
read -r ADMIN_ID

mkdir -p /root/monitor_bot
cp -r monitor_bot/* /root/monitor_bot/

cat > /root/monitor_bot/config.py <<EOF
TOKEN = "$BOT_TOKEN"
ADMIN_ID = $ADMIN_ID
EOF

apt update && apt install git
apt install -y python3 python3-pip
pip3 install -r /root/monitor_bot/requirements.txt

cp vpn_bot.service /etc/systemd/system/vpn_bot.service

systemctl daemon-reload
systemctl enable --now vpn_bot.service

echo "Установка завершена! Ваш VPN-бот запущен. Для управления OpenVPN используйте /root/install_openvpn_xormask.sh"