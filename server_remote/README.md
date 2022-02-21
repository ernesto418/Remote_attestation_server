# Introduction

It is a version of the real server (go to default branch to more details). In this version, the server will always accept and respond ok in Attest.
 
# No container

## Build

Install Maven:
```
$ sudo apt install maven
```
Build project:
 ```
 $ mvn install
``` 
JAR file location: `server/target/server-0.0.1-SNAPSHOT.jar`

## Run

Install openJDK:
```
$ sudo apt-get install openjdk-9-jre
```
Run server. On Raspberry Pi you may need root privilege to access port 80/443.
```
$ sudo java -jar server-0.0.1-SNAPSHOT.jar
```
# Container 

## Step 1: Build the image

```
  docker build -t server_remote_attestation_img:v2 .
```
## Step 2: Create the container  
```
 docker create --name server_remote_attestation -p 3000:3000 -p 443:443 server_remote_attestation_img:v2
```
## Step 3: Start the docker container

```
  docker start server_remote_attestation 

```
# License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
