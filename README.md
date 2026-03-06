# Mungos проект анализа трафика
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
docker-compose -f deploy/docker-compose.sniffer.yml up -d
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





## Настройки и команды для разработки:
### Core со своей БД и Prometheus
```sh
docker-compose -f deploy/docker-compose.master.yml up -d
docker-compose -f deploy/docker-compose.master.yml up -d --build core-app
docker-compose -f deploy/docker-compose.master.yml watch
```
### Sniffer со своей БД
```sh
docker-compose -f deploy/docker-compose.sniffer.yml up -d
docker-compose -f deploy/docker-compose.sniffer.yml up -d --build sniffer-app
docker-compose -f deploy/docker-compose.sniffer.yml watch
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
TRUNCATE TABLE sniffer_clients;
```
### PostgreSQL
```sh
docker exec -it mungos-postgres-core psql -U mungos -d mungos_core
SELECT * FROM sniffers;
TRUNCATE TABLE sniffers;
```
