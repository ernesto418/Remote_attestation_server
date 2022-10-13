FROM ubuntu:18.04
COPY server/target target

RUN apt-get update && apt-get install -y  default-jdk

CMD cd /
CMD cd target &&  java -jar server-0.0.1-SNAPSHOT.jar
