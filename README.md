# Core со своей БД и Prometheus
docker-compose -f deploy/docker-compose.master.yml up -d


# Sniffer со своей БД
docker-compose -f deploy/docker-compose.sniffer.yml up  -d