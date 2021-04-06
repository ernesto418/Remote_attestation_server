FROM ubuntu:18.04
COPY server server
COPY pom.xml pom.xml
RUN apt-get update && apt-get install -y maven default-jdk sudo
RUN mvn install

CMD cd /
CMD cd server/target && sudo java -jar server-0.0.1-SNAPSHOT.jar
