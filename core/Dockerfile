FROM eclipse-temurin:21-jdk-alpine AS builder
WORKDIR /app
COPY ../core/. .
RUN ./mvnw clean package -DskipTests

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=builder /app/target/core.jar core.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "core.jar"]