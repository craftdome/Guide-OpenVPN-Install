# Guide-OpenVPN-Install
Установка OpenVPN сервера на базе 2 центров сертификации (ЦС)

## Шаг 1. Подготовка
На этом шаге нужно подготовить рабочие машины, где будет производиться установка `OpenVPN+SubCA` и `RootCA`, и сгенерировать пароли для ЦС.
В руководстве два ЦС установлены на одной машине в разных каталогах (RootCA и SubCA), но всё выглядит так, будто это две разные ВМ.
Для передачи файлов (запросов, ключей) между серверами воспользуйтесь ftp клиентом для удобства, например, FileZilla или *Bitvise SSH Client*.

|Назначение| Автономный|VPN-сервер|
| :--- | :--- | :--- |
|ОС|Debian 11 (bullseye)|Debian 11 (bullseye)|
|Пользователь|user|user|
|Программное обеспечение|EasyRSA|EasyRSA+OpenVPN|
|Пароль ЦС|BH%<#do$rZ-4Z'6Q#76^| |
|ip|192.168.1.10|192.168.1.20 |
|Интерфейс|ens32|ens32|

## Шаг 2. Создание ЦС (Автономный сервер)

1. Скачивание и распаковка EasyRSA.
```
apt install openssl
wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.1/EasyRSA-3.1.1.tgz
tar -zxf EasyRSA-3.1.1.tgz
mv EasyRSA-3.1.1 RootCA
cd RootCA
```
> Дополнительно нужен фикс бага (версия 3.1.1): `nano ./easyrsa` -> строка 1320 -> заменяем die на warn

2. Инициализация PKI.
```
./easyrsa init-pki
```
> `/root/RootCA/pki/ca.crt` - публичный ключ (нужно скопировать для других ЦС)
> `/root/RootCA/pki/ca.key` - приватный ключ (используется для подписи сертификатов серверов и клиентов)

3. Меняем конфигурацию.
```
cp vars.example pki/vars  // Базовая конфигурация
nano pki/vars				      // Редактируем конфигурацию как нам нужно, можно оставить по умолчанию
```

4. Создание ЦС.
```
./easyrsa build-ca
```
> Enter New CA Key Passphrase: BH%<#do$rZ-4Z'6Q#76^

> Re-Enter New CA Key Passphrase: BH%<#do$rZ-4Z'6Q#76^

> Common Name (eg: your user, host, or server name) [Easy-RSA CA]: RootCA

## Шаг 3. Создание ЦС и подготовка OpenVPN (VPN-сервер)

1. Скачивание и распаковка `EasyRSA` и `OpenVPN`.
```
apt install openvpn
wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.1/EasyRSA-3.1.1.tgz
tar -zxf EasyRSA-3.1.1.tgz
mv EasyRSA-3.1.1 SubCA
cd SubCA
```
> Дополнительно нужен фикс бага (версия 3.1.1): `nano ./easyrsa` -> строка 1320 -> заменяем die на warn

2. Инициализация PKI (подчинённого ЦС).
```
./easyrsa init-pki
```
> `/root/SubCA/pki/ca.crt`
> `/root/SubCA/pki/ca.key`

3. Меняем конфигурацию.
```
cp vars.example pki/vars	// Базовая конфигурация
nano pki/vars				      // Редактируем конфигурацию как нам нужно, можно оставить по умолчанию
```

4. Запрос на создание сертификата ЦС.
```
./easyrsa gen-req SubCA nopass
```
> Если нужен пароль для SubCA, то убираем `nopass` из команды

> `/root/SubCA/pki/reqs/SubCA.req`		- файл запрос сертификата

> `/root/SubCA/pki/private/SubCA.key`	- закрытый ключ для этого ЦС

5. Копируем закрытый ключ в OpenVPN.
```
cp /root/SubCA/pki/private/SubCA.key /etc/openvpn
```

6. Файл запроса сертификата `SubCA.req` нужно передать на **Автономный сервер**.
> Можно вручную передать файл по FTP, если автономный сервер отключён от сети, а можно с помощью `scp`.
```
scp /root/SubCA/pki/reqs/SubCA.req user@ROOT_CA_IP:/tmp
```

7. Подключаемся к **Автономному серверу** и подписываем запрос.
```
ssh user@ROOT_CA_IP
cd /root/RootCA
./easyrsa import-req /tmp/SubCA.req SubCA
./easyrsa sign-req server SubCA
```
> Подтверждаем надёжность источника - yes

> Вводим пароль от RootCA, если он установлен

> `/root/RootCA/pki/issued/SubCA.crt` - результат

8. Передаём подписанный сертификат на VPN-сервер, а также корневой сертификат.
```
scp /root/RootCA/pki/issued/SubCA.crt user@SUB_CA_IP:/tmp
scp /root/RootCA/pki/ca.crt user@SUB_CA_IP:/tmp
```

9. Продолжаем на VPN-сервере, копируем сертификаты в `/etc/openvpn`.
```
cp /tmp/{SubCA.crt,ca.crt} /etc/openvpn
```

10. Создаём ключ Диффи-Хелмана.
```
cd /root/SubCA
./easyrsa gen-dh
```
> `/root/SubCA/pki/dh.pem`

11. Создаём подпись HMAC, чтобы усилить функции проверки целостности TLS.
```
openvpn --genkey secret ta.key
```
> `/root/SubCA/ta.key`

12. Копируем созданные файлы в `/etc/openvpn`.
```
cp /root/SubCA/ta.key /etc/openvpn
cp /root/SubCA/pki/dh.pem /etc/openvpn
```

13. Создаём каталог для клиентских сертификатов (все созданные сертификаты клиентов будут здесь).
```
mkdir -p /root/clients/keys
chmod -R 700 /root/clients/keys
```

## Шаг 4. Настройка сервиса OpenVPN (VPN-сервер)

1. Копируем пример конфига **server.conf** и открываем его на редактирование.
```
cp /usr/share/doc/openvpn/examples/sample-config-files/server.conf /etc/openvpn/
nano /etc/openvpn/server.conf
```

2. Устанавливаем следующие настройки.
> Выставлены такие настройки, которые максимально маскируют поведение OpenVPN на сетевом уровне.

> В идеале, чтобы VPN-сервер стоял на резидентском IP, но такой хостинг сложно найти (как пример, inferno.name).

> Не должно быть также PTR записи для IP сервера, что часто встречается (как пример, OVH, PTR запись: vps-c4adsa23.vps.ovh.net).
```
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login // PAM авторизация, можно удалить, если она не нужна

mssfix 0      # изменяем MTU на максимально возможный, чтобы избавиться от сигнатуры OpenVPN

port 443      # Порт 443, чтобы маскировать трафик под базовый порт https
proto tcp     # Аналогично 443, https работает поверх tcp
dev tun

tls-auth ta.key 0 # Подключаем TLS аутентификацию (как у https)
key-direction 0

server 10.8.0.0 255.255.0.0

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"					# DNS-сервера Google, желательно поставить свои, если вам не нравится, что ваши запросы логгируется гуглом
push "dhcp-option DNS 8.8.4.4"
push "block-outside-dns"                # Блокируем запросы DNS мимо VPN

cipher AES-256-CBC
auth SHA256

ca ca.crt
cert SubCA.crt
key SubCA.key
dh dh.pem

user nobody
group nogroup

explicit-exit-notify 0  // если proto tcp
```

## Шаг 5. Настройка сети (VPN-сервер)

1. Включаем маршрутизацию трафика через сервер `nano /etc/sysctl.conf` после запуска сервера.
```
net.ipv4.ip_forward=1
```

2. Активируем маршрутизацию принудительно.
```
sysctl -p
```

3. Определяем открытый сетевой интерфейс.
```
ip route | grep default
```
> Пример вывода: `default via 192.168.88.1 dev ens32`

4. Включение **MASQUERADE** и открытие порта **443** подключения к OpenVPN для пользователей.
```
iptables -t nat -A POSTROUTING -s 10.8.0.0/16 -o ens32 -j MASQUERADE
iptables -A INPUT -i ens32 -p tcp -m tcp --dport 443 -j ACCEPT
```

5. Включаем политику **ACCEPT** на цепочку **FORWARD**.
```
iptables -P FORWARD ACCEPT
```

6. Бекап правил iptables (если была настроена защита сети https://github.com/Tyz3/Guide-Basic-Server).
```
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
```

7. Если автозапуск не настроен, то добавляем правила iptables на **автозапуск**.
```
apt install iptables-persistent
```

## Шаг 6. Запуск и автозагрузка сервиса OpenVPN (VPN-сервер)

1. Запускаем OpenVPN сервер с конфигом **server.conf**, включаем автозапуск.
```
systemctl start openvpn@server
systemctl status openvpn@server
systemctl enable openvpn@server
```

2. Проверяем наличие интерфейса **tun0**.
```
ip addr show tun0
```

## Шаг 7. Генерация ключей пользователя VPN (VPN-сервер)

1. Создаём запрос на сертификат с любым именем.
```
cd /root/SubCA
./easyrsa gen-req client1 nopass
```
> Common Name [client1]:

> `/root/SubCA/pki/private/client1.key`

2. Копируем приватный ключ в каталог клиентов.
```
cp pki/private/client1.key /root/clients/keys
```
> `/root/clients/keys/client1.key`

3. Перемещаем файл-запрос на сервер с **RootCA**.
```
scp /root/SubCA/pki/reqs/client1.req user@root_ca_ip:/tmp
```

4. (На сервере **RootCA**) Импортируем запрос **client1.req**.
```
cd /root/RootCA
./easyrsa import-req /tmp/client1.req client1
```

5. Подписываем запрос с типом **client**.
```
./easyrsa sign-req client client1
```
> Вводим пароль от **RootCA** (_BH%<#do$rZ-4Z'6Q#76^_)
> `/root/RootCA/pki/issued/client1.crt`

7. Передаём **client1.crt** на сервер с **SubCA**.
```
scp /root/RootCA/pki/issued/client1.crt router@192.168.88.202:/tmp
```

8. (На сервере **SubCA**) Копируем **client1.crt** в каталог ключей клиентов.
```
cp /tmp/client1.crt /root/clients/keys/
```
> `/root/clients/keys/client1.crt`

## Шаг 8. Создание клиентских конфигураций (скрипт) (VPN-сервер)
Осталось собрать все созданные файлы в один конфиг, который можно использовать для подключения к VPN.

1. Создаём каталог для хранения файлов и копируем образец конфига.
```
mkdir -p /root/clients/files
cp /usr/share/doc/openvpn/examples/sample-config-files/client.conf /root/clients/base.conf
```

2. Настройка `nano /root/clients/base.conf`.
```
auth-user-pass    // PAM авторизация, можно удалить, если она не нужна

dev tun
proto tcp

remote 192.168.1.20 443

user nobody
group nogroup

;ca ca.crt
;cert client.crt
;key client.key

;tls-auth ta.key 1

cipher AES-256-GCM
auth SHA256

key-direction 1

# Для Linux пользователей
;script-security 2
;up /etc/openvpn/update-resolv-conf
;down /etc/openvpn/update-resolv-conf
```

3. Создаём **make_config.sh**.
```
touch /root/clients/make_config.sh
chmod +x /root/clients/make_config.sh
```

4. Вставляем содержимое **make_config.sh** `nano /root/clients/make_config.sh`.
```
#!/bin/bash
# First argument: ClientName

ROOT_DIR="/root"
OVPN_DIR="/etc/openvpn"
CLIENTS_DIR="${ROOT_DIR}/clients"

cd "${CLIENTS_DIR}"

KEY_DIR="${CLIENTS_DIR}/keys"
OUTPUT_DIR="${CLIENTS_DIR}/files"
BASE_CONFIG="${CLIENTS_DIR}/base.conf"

rm -rf $OUTPUT_DIR/${1}.ovpn
mkdir -p $OUTPUT_DIR/

CFG=$(cat $BASE_CONFIG)
CA=$(cat $OVPN_DIR/ca.crt)
TA=$(cat $OVPN_DIR/ta.key)
CLIENT_CRT=$(cat $KEY_DIR/${1}.crt)
CLIENT_KEY=$(cat $KEY_DIR/${1}.key)

echo -e "$CFG\n<ca>\n$CA\n</ca>\n<cert>\n$CLIENT_CRT\n</cert>\n<key>\n$CLIENT_KEY\n</key>\n<tls-auth>\n$TA\n</tls-auth>" > $OUTPUT_DIR/${1}.ovpn
echo "Файл конфигурации OpenVPN создан: $OUTPUT_DIR/${1}.ovpn"
```

## Шаг 9. Создание конфига OpenVPN

1. Создаём файл конфигурации **.ovpn**.
> `client_name` - это название сертификата, который был создан на шаге 7 **Генерация ключей пользователя VPN**
```
/root/clients/make_config.sh client_name
```

2. Добавляем пользователя для PAM-авторизации OpenVPN.
```
useradd -s /usr/sbin/nologin ovpn_user1
```

# Цепочка из нескольких VPN
Чтобы настроить связку нескольких VPN достаточно выполнить следующие действия.

Предположим мы хотим создать цепочку из двух VPN: **Пользователь** - **VPN1** - **VPN2** - **Интернет**.

## Шаг 1. Сервер **VPN2**

1. Изменения в `server.conf`.
```
;plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login

server 10.9.0.0 255.255.0.0

;push "redirect-gateway def1 bypass-dhcp"
;push "block-outside-dns"
```

2. Изменения в `base.conf`. Если на VPN2 уже созданы файлы `.ovpn`, то следует изменить.
> tun1 - статическое название интерфейса, чтобы случайно не занять tun0.
```
dev tun1

;auth-user-pass

script-security 2
up upstream-route.sh
```

3. Создаём сертификат `server1.ovpn` и меняем расширение на `.conf`.
```
mv server1.ovpn server1.conf
```

4. Созданный сертификат передаём на сервер **VPN1** в каталог `/etc/openvpn`.

## Шаг 2. Сервер **VPN1**

1. В файле `/etc/iptables/rules.v4` интерфейс `ens32` меняем на `tun1`. И перезапускаем сервер `reboot`.
```
# Generated by iptables-save v1.8.7 on Tue Jan 17 15:27:02 2023
*filter
:INPUT DROP [304381:11521477]
:FORWARD ACCEPT [11033737:9799600824]
:OUTPUT ACCEPT [6088285:9097343685]
-A INPUT -i ens32 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -i ens32 -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -i ens32 -p tcp -m tcp --dport 443 -j ACCEPT
COMMIT
# Completed on Tue Jan 17 15:27:02 2023
# Generated by iptables-save v1.8.7 on Tue Jan 17 15:27:02 2023
*nat
:PREROUTING ACCEPT [329310:15972893]
:INPUT ACCEPT [9108:434663]
:OUTPUT ACCEPT [2602:201144]
:POSTROUTING ACCEPT [2603:201215]
-A POSTROUTING -s 10.8.0.0/16 -o tun1 -j MASQUERADE
COMMIT
# Completed on Tue Jan 17 15:27:02 2023
```

2. Создаём скрипт настройки маршрутов сети `/etc/openvpn/upstream-route.sh`.
> `chmod +x /etc/openvpn/upstream-route.sh`
```
#!/bin/bash

ip rule add from 10.8.0.0/24 table 120
ip route add default dev tun1 table 120

exit 0
```

3. Подключение **VPN1** к **VPN2**. Так как конфиг `server1.conf` уже передан на VPN1 и лежит в `/etc/openvpn`, мы можем запустить сервис openvpn.
```
systemctl start openvpn@server1
systemctl enable openvpn@server1
```

4. Проверяем наличие интерфейса **tun1**. Если интерфейс присутствует, то всё сделано правильно, можно проверять подключение.
```
ip addr show tun1
```
