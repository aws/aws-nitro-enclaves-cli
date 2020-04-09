FROM ubuntu:latest
  COPY command-executer .
  RUN apt-get update && apt-get install -y \
      apt-utils
  CMD ./command-executer listen --port 5005
