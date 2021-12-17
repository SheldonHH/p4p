FROM ubuntu:20.04
RUN apt-get update && apt-get install git-all
git clone https://github.com/sheldonhh/p4p.git
git clone https://github.com/fedproject/grpc-go.git
git clone https://github.com/fedproject/grpc-java.git

RUN apt-get install default-jre
RUN apt-get install default-jdk
