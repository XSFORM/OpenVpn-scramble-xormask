# OpenVpn scramble-xormask

## Быстрый старт: OpenVPN-сервер + Telegram-монитор-бот

## Debian 11

Этот проект помогает развернуть современный OpenVPN-сервер и Telegram-бота для его мониторинга и управления.

---

## Установка

1. **Клонируйте репозиторий:**
   ```bash
   git clone https://github.com/XSFORM/OpenVpn-scramble-xormask.git
   cd OpenVpn-scramble-xormask
   ```

2. **Дайте права на запуск:**
   ```bash
   chmod +x install.sh install_openvpn_xormask.sh
   ```

3. **Запустите установку:**
   ```bash
   ./install.sh
   ```

4. **Следуйте инструкции:**
   - Введите токен Telegram-бота.
   - Введите свой Telegram ID.

5. **После завершения установки ОБЯЗАТЕЛЬНО перезапустите терминал.**

   
---

## Управление OpenVPN

1. **Дайте права на запуск:**
   ```bash
   chmod +x openvpn-install.sh
   ```

2. **Для создания, удаления и управления VPN-клиентами используйте:**
   ```bash
   ./openvpn-install.sh
   ```
(Скрипт будет доступен из `/root` — можно запускать из любой директории, если перейти в `/root`, либо прямо из вашей домашней папки root.)

---

## Telegram-бот

- Бот запускается как systemd-сервис и работает автоматически.
- Для управления сервисом:
  ```bash
  systemctl status vpn_bot.service
  systemctl restart vpn_bot.service
  ```

---

## Прочее

- Перезапуск openvpn
  ```bash
  sudo systemctl restart openvpn@server

- Ваши токены и ID хранятся только в `/root/monitor_bot/config.py` и не попадают в репозиторий.
- Для обновления — просто скачайте новую версию репозитория, повторите установку, ваши ключи сохранятся.

---

## Автор

XSFORM  
Telegram: [@XSFORM](https://t.me/XSFORM)