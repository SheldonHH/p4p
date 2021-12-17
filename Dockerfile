RUN apt update
RUN apt-get install git-all
git clone http://github.com/sheldonhh/p4p.git
git clone http://github.com/fedproject/grpc-go.git
git clone http://github.com/fedproject/grpc-java.git

RUN apt install default-jre
RUN apt install default-jdk
