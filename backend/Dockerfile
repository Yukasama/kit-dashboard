FROM eclipse-temurin:23-jdk-alpine AS builder
WORKDIR /app
COPY ./build.gradle ./settings.gradle ./gradlew ./
COPY ./gradle ./gradle
RUN ./gradlew build --no-daemon -x test

COPY ./src ./src
RUN ./gradlew bootJar

FROM eclipse-temurin:23-jre-alpine
WORKDIR /app
COPY --from=builder /app/build/libs/*.jar app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
