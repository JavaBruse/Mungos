<h1>
  <img src="frontend/public/label_clear.png" width="100" height="100" alt="Mungos logo" style="vertical-align: middle;">
  Mungos — проект анализа трафика
</h1>

- Клонируем проект
```sh
git clone https://github.com/JavaBruse/Mungos.git
```
В проекте настроен полный цикл сборки компиляции загрузки зависимостей и упаковки в контейнер. В связи с чем не требуется никаких отдельных настроек и модификаций среды выполнения.
- Сборка и запуск основного модуля из корня проекта
```sh
docker-compose -f deploy/docker-compose.master.yml up -d --build
```
- Сборка и запуск сниффера

Сниффер работает как отдельный модуль. Для его подключения к системе необходимо знать IP-адрес сервера.
При локальном запуске (на одной машине с сервером) веб-форма добавления сниффера всегда будет содержать корректные host (имя контейнера) и port настроенных по умолчанию.
```sh
docker-compose -f deploy/docker-compose.sniffer.yml up -d --build
```
- Для доступа к WEB перейдите по ссылке: 
```text
http://localhost
``` 
- При входе всегда запрашивает логин пароль, если JWT не был получен ранее.
- При первом запуске создается учетная запись по умолчанию,
```text
login: admin
password: admin
```
так же система сразу требует обновить пароль.

- admin имеет роль ADMIN_ROLE, у коротой все права на любые действия. У остальных ролей только просмотр.

### Для работы фингерпринтинга требуется скачать базу данных

- База скачается сама если будет доступен ресурс. Иначе можно скачать в ручную:
```bash
cd deploy
mkdir data
wget https://ja4db.com/api/download/ -O ./data/ja4db.json
//или с google
wget "https://drive.usercontent.google.com/download?id=1U4Od-5OpLJxvTNp54-ZKBUMFIjhp-wDr&export=download&confirm=t" -O ~/Mungos/deploy/data/ja4db.json
```

- База вендоров взята из источника
```http
https://standards-oui.ieee.org/oui/oui.txt
```
- Лежит по пути deploy/data/oui.txt


Все переменные задаются в файле [`/deploy/.env`](/deploy/.env)

```text
# Core
DB_NAME=mungos_core
DB_USER=mungos
DB_PASS=mungos123
DB_HOST=postgres-core
DB_PORT=5432
CORE_PORT=7779
FRONT_PORT=80
SPRING_PROFILES_ACTIVE=docker
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin
BACKEND_HOST=localhost
JWT_SECRET=9f8e7d6c5b4a3z2y1x0w9v8u7t6s5r4q3p2o1n2m3l4k5j6i7h8g9f8e7d6c5b4a3z
# настройки для фронта, на адрес бэка
API_URL=http://localhost:7779/ 

TZ=Europe/Moscow
# Sniffer
SNIFFER_DB_NAME=snifferdb
SNIFFER_DB_USER=snifferuser
SNIFFER_DB_PASS=snifferpass
SNIFFER_DB_HOST=clickhouse-sniffer
SNIFFER_DB_PORT=9000
SNIFFER_DB_PROTOCOL=native
SNIFFER_GRPC_PORT=3331
SNIFFER_NAME=172.20.0.10
SNIFFER_DEVICE=eth0
SNIFFER_PROMISC=true
SNIFFER_FILTER=
SNIFFER_LOG=packets.log
SNIFFER_ID=sniffer-1
DEFAULT_MASTER_KEY=default-master-key-123
DB_TYPE=clickhouse

# Prometheus
PROMETHEUS_URL=http://prometheus:9090
```



## Настройки и команды для разработки:
### Core со своей БД и Prometheus
```sh
docker-compose -f deploy/docker-compose.master.yml up -d
docker-compose -f deploy/docker-compose.master.yml up -d --build core-app
docker-compose -f deploy/docker-compose.master.yml down
docker-compose -f deploy/docker-compose.master.yml watch
```
### Sniffer со своей БД
```sh
docker-compose -f deploy/docker-compose.sniffer.yml up -d
docker-compose -f deploy/docker-compose.sniffer.yml up -d --build sniffer-app
docker-compose -f deploy/docker-compose.sniffer.yml down
docker-compose -f deploy/docker-compose.sniffer.yml watch
```

### Sniffer-host со своей БД
```sh
docker-compose -f deploy/docker-compose.sniffer-host.yml up -d
docker-compose -f deploy/docker-compose.sniffer-host.yml up -d --build sniffer-app
docker-compose -f deploy/docker-compose.sniffer-host.yml down
docker-compose -f deploy/docker-compose.sniffer-host.yml watch
```
### Удалить тома
```sh
docker volume rm mungos_clickhouse_sniffer-data
docker volume rm mungos_postgres-core-data
docker volume rm mungos_prometheus-data
```
### Удалить все тома сразу
```sh
docker volume prune -f
```
### Подключение к базе данных
### ClickHause
```sh
docker exec -it mungos-clickhouse-sniffer clickhouse-client
USE snifferdb;
SELECT * FROM sniffer_clients;
SELECT * FROM sni_stats;
TRUNCATE TABLE sniffer_clients;
DROP TABLE IF EXISTS ja4_database;
```
### PostgreSQL
```sh
docker exec -it mungos-postgres-core psql -U mungos -d mungos_core
SELECT * FROM sniffers;
TRUNCATE TABLE sniffers;
```



BPF фильтры в Sniffer
Основные правила
1. IP адреса
```text
host 192.168.1.1              - трафик с/на 192.168.1.1
src host 192.168.1.1          - только исходящий с 192.168.1.1
dst host 192.168.1.1          - только входящий на 192.168.1.1
```
2. Порты
```text
port 80                        - трафик через порт 80
src port 443                   - исходящий с порта 443
dst port 53                    - входящий на порт 53
port range 1000-2000           - диапазон портов
```
3. Комбинации
```text
host 192.168.1.1 and port 80   - IP 192.168.1.1 И порт 80
host 10.0.0.1 or port 443      - IP 10.0.0.1 ИЛИ порт 443
(host 192.168.1.1 and port 80) or (host 10.0.0.1 and port 443)
```
4. Исключения (NOT)
```text
not port 80                    - всё кроме порта 80
not host 192.168.1.1           - всё кроме IP 192.168.1.1
not (host 192.168.1.1 and port 80) - исключить комбинацию
```
5. Протоколы
```text
tcp                            - только TCP трафик
udp                            - только UDP трафик
icmp                           - только ICMP
tcp port 80                    - TCP порт 80
udp port 53                    - UDP порт 53
```
Примеры
Исключить свой трафик:
```text
not (host 172.20.0.10 or host 172.20.0.5)
```
Мониторить только внешние подключения:
```text
not (src net 192.168.0.0/16 or dst net 192.168.0.0/16)
```
Сложное исключение:
```text
not (host 172.20.0.10 and port 3331) and not port 3123 and not host 172.20.0.2
```