FROM ubuntu:20.04

RUN apt-get update 
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
RUN apt-get install build-essential cmake git python3 -y
RUN apt-get install bash
