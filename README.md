# Core со своей БД и Prometheus
docker-compose -f deploy/docker-compose.master.yml up -d
docker-compose -f deploy/docker-compose.master.yml up -d --build core-app
docker-compose -f deploy/docker-compose.master.yml watch

# Sniffer со своей БД
docker-compose -f deploy/docker-compose.sniffer.yml up  -d
docker-compose -f deploy/docker-compose.sniffer.yml up -d --build sniffer-app
docker-compose -f deploy/docker-compose.sniffer.yml watch

# Подключение к базе данных
docker exec -it mungos-postgres-core psql -U mungos -d mungos_core


docker-compose down

# Удалить тома
docker volume rm mungos_clickhouse_sniffer-data
docker volume rm mungos_postgres-core-data
docker volume rm mungos_prometheus-data

# Или удалить все тома сразу
docker volume prune -f


Кликхаус
docker exec -it mungos-clickhouse-sniffer clickhouse-client
USE snifferdb;
SELECT * FROM sniffer_clients;
TRUNCATE TABLE sniffer_clients;


 docker exec -it mungos-postgres-core psql -U mungos -d mungos_core
 SELECT * FROM sniffers;
 TRUNCATE TABLE sniffers;