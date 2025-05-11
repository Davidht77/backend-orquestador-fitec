# Imagen base con Java (usa una versión compatible con tu JAR)
FROM eclipse-temurin:21-jdk-alpine

# Directorio de trabajo en el contenedor
WORKDIR /app

# Copia el JAR al contenedor
COPY target/orquestador-0.0.1-SNAPSHOT.jar app.jar

# Expone el puerto (cámbialo si tu app usa otro)
EXPOSE 8080

# Comando para ejecutar el JAR
ENTRYPOINT ["java", "-jar", "app.jar"]