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




---СЕРТИФИКАТ---
# Генерируем корневой CA
openssl genrsa -out certs/ca.key 2048
openssl req -new -x509 -key certs/ca.key -out certs/ca.crt -subj "/CN=SnifferCA"

# Генерируем сертификат для снифера (без привязки к адресам)
openssl genrsa -out certs/sniffer.key 2048
openssl req -new -key certs/sniffer.key -out certs/sniffer.csr -subj "/CN=*"
openssl x509 -req -in certs/sniffer.csr -CA certs/ca.crt -CAkey certs/ca.key -set_serial 01 -out certs/sniffer.crt