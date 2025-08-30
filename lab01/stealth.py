import sys
import time
import struct
from scapy.all import IP, ICMP, send

# Longitud deseada del payload en bytes
PAYLOAD_LEN = 56

def crear_payload(caracter: str) -> bytes:
    now = time.time()
    secs = int(now)
    usecs = int((now - secs) * 1_000_000)

    # Timestamp en 8 bytes (2 enteros de 4 bytes, big endian)
    timestamp = struct.pack("!II", secs, usecs)

    # Carácter a enviar (1 byte)
    char_byte = caracter.encode()

    # Calcular padding necesario
    used = len(timestamp) + len(char_byte)
    padding_len = PAYLOAD_LEN - used

    if padding_len < 0:
        raise ValueError("El payload calculado excede los 48 bytes")

    # Padding incremental hasta llegar a los 48 bytes exactos
    padding = bytes(((0x0a + i) & 0xFF) for i in range(padding_len))

    payload = timestamp + char_byte + padding

    # Verificación final
    if len(payload) != PAYLOAD_LEN:
        raise ValueError(f"Payload inválido: {len(payload)} bytes en vez de {PAYLOAD_LEN}")

    return payload


def enviar_mensaje_icmp(destino: str, mensaje: str):
    print(f"Enviando mensaje oculto a {destino}...\n")

    # Todos los caracteres salvo el último
    for i, char in enumerate(mensaje[:-1]):
        payload = crear_payload(char)
        paquete = IP(dst=destino)/ICMP(type=8, id=12345, seq=i)
        paquete = paquete / payload  # fuerza el load exacto
        print(f"[+] Paquete {i+1} con carácter '{char}' ({len(payload)} bytes)")
        send(paquete, verbose=False)

    # Último carácter como delimitador
    delimitador = mensaje[-1]
    payload_final = crear_payload(delimitador)
    paquete = IP(dst=destino)/ICMP(type=8, id=12345, seq=len(mensaje))
    paquete = paquete / payload_final
    print(f"[+] Paquete final con delimitador '{delimitador}' ({len(payload_final)} bytes)")
    send(paquete, verbose=False)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: sudo python3 stealth.py \"<mensaje_cifrado>\"")
        sys.exit(1)

    destino = "57.144.150.1"
    mensaje = sys.argv[1]
    enviar_mensaje_icmp(destino, mensaje)