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