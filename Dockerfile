FROM ubuntu:20.04
RUN apt-get update && apt-get install git-all
git clone http://github.com/sheldonhh/p4p.git
git clone http://github.com/fedproject/grpc-go.git
git clone http://github.com/fedproject/grpc-java.git

RUN apt-get install default-jre
RUN apt-get install default-jdk
