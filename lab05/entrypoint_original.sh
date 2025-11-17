#!/bin/bash
set -e

echo "Iniciando configuración del servidor S1..."

# 1. Instalar el servidor OpenSSH
apt-get update
apt-get install -y openssh-server

# 2. Crear el usuario "prueba" con contraseña "prueba"
useradd -m -s /bin/bash prueba
echo "prueba:prueba" | chpasswd
echo "Usuario 'prueba' creado."

# 3. Configurar el servidor SSH
mkdir /var/run/sshd
# Habilitar autenticación por contraseña
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
# Deshabilitar login de root
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
# Permitir solo al usuario prueba
echo "AllowUsers prueba" >> /etc/ssh/sshd_config

# 4. Generar las claves del host
ssh-keygen -A

echo "Servidor SSH configurado. Iniciando..."

# 5. Iniciar el servicio SSH en primer plano
exec /usr/sbin/sshd -D