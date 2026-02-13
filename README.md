# Core со своей БД и Prometheus
docker-compose -f deploy/docker-compose.master.yml up -d
docker-compose -f deploy/docker-compose.master.yml build core-app
docker-compose -f deploy/docker-compose.master.yml up -d core-app

# Sniffer со своей БД
docker-compose -f deploy/docker-compose.sniffer.yml up  -d
docker-compose -f deploy/docker-compose.sniffer.yml build sniffer-app
docker-compose -f deploy/docker-compose.sniffer.yml up -d sniffer-app

# Подключение к базе данных
docker exec -it mungos-postgres-core psql -U mungos -d mungos_core