# Introduction

Remote attestation is a mechanism to enable a remote system (server) to determine the integrity of a platform of another system (Raspberry Pi®). In a Linux-based system, a security feature known as the Integrity Measurement Architecture (IMA) can be used to capture platform measurements. Together with TPM a hardware-based security and its set of attestation features, it can be used to perform authentication and to protect the IMA measurement.

It is a modified version based on Application Note at [link](https://github.com/Infineon/remote-attestation-optiga-tpm/tree/master/documents). The version of this repository is called RESEKRA and it is published in https://www.mdpi.com/1424-8220/22/13/5060.

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
