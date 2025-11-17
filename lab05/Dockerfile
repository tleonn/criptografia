ARG UBUNTU_VERSION=22.04
FROM ubuntu:${UBUNTU_VERSION}

ENV DEBIAN_FRONTEND=noninteractive

# Instalar el cliente SSH y utilidades básicas
RUN apt-get update && apt-get install -y \
    openssh-client \
    sudo \
    nano \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Copia el script de entrada que configurará el servidor S1
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh