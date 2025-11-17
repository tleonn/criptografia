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
mkdir -p /var/run/sshd
# Habilitar autenticación por contraseña
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
# Deshabilitar login de root
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
# Permitir solo al usuario prueba
echo "AllowUsers prueba" >> /etc/ssh/sshd_config

# 3b. MODIFICAR ALGORITMOS PARA REDUCIR EL PAQUETE KEX INIT
echo "Modificando algoritmos de SSHD para reducir tamaño de KexInit..."
echo "" >> /etc/ssh/sshd_config
echo "# --- INICIO DE MODIFICACIONES KEXINIT ---" >> /etc/ssh/sshd_config
echo "KexAlgorithms curve25519-sha256@libssh.org" >> /etc/ssh/sshd_config
echo "Ciphers aes128-ctr" >> /etc/ssh/sshd_config
echo "MACs hmac-sha2-256" >> /etc/ssh/sshd_config
echo "HostKeyAlgorithms ssh-ed25519" >> /etc/ssh/sshd_config
echo "Compression no" >> /etc/ssh/sshd_config
echo "# --- FIN DE MODIFICACIONES KEXINIT ---" >> /etc/ssh/sshd_config

# 4. Generar las claves del host
ssh-keygen -A

echo "Servidor SSH configurado y modificado. Iniciando..."

# 5. Iniciar el servicio SSH en primer plano
exec /usr/sbin/sshd -D