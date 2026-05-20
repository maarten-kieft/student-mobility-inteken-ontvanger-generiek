FROM maven:3.9.6-eclipse-temurin-21-alpine AS builder
WORKDIR /app
COPY . .
RUN mvn clean package -DskipTests -Dmaven.gitcommitid.skip=true

FROM eclipse-temurin:21-jdk-alpine
RUN apk --update upgrade && apk add openssl openssl-dev ca-certificates libgcc && update-ca-certificates
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
ENTRYPOINT ["java","-jar","/app/app.jar"]