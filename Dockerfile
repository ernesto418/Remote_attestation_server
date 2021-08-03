FROM maven:3.6.3-openjdk-17-slim
COPY server server
COPY pom.xml pom.xml



WORKDIR "/server/target"
CMD ["java", "-jar", "./server-0.0.1-SNAPSHOT.jar"]
