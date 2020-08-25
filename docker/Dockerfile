FROM ubuntu:20.04

RUN apt-get update 
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
RUN apt install build-essential cmake git python3 python3-pip bash -y
RUN cd /usr/bin && ln -s /usr/bin/python3 python