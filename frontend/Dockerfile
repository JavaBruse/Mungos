FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN echo "export const environment = { production: true, apiUrl: '${API_URL}', portSniffer: '${SNIFFER_GRPC_PORT}', SNIFFER_NAME: '172.20.0.10' };" > src/environments/environment.prod.ts
RUN npm run build --prod

FROM nginx:alpine
RUN rm -rf /usr/share/nginx/html/*
COPY --from=builder /app/dist/frontend/browser /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 3000
CMD ["nginx", "-g", "daemon off;"]