import sys
import re
from scapy.all import rdpcap, ICMP

class Colors:
    """Códigos de color ANSI para terminal"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

def extraer_mensaje_icmp(archivo_pcap):
    """
    Extrae el mensaje oculto de los paquetes ICMP en el archivo PCAP.
    Busca paquetes con ID 12345 y ordena por número de secuencia.
    """
    try:
        paquetes = rdpcap(archivo_pcap)
    except Exception as e:
        print(f"{Colors.RED}Error al leer el archivo PCAP: {e}{Colors.END}")
        return None
    
    # Filtrar paquetes ICMP con ID específico
    paquetes_icmp = []
    for pkt in paquetes:
        if ICMP in pkt and pkt[ICMP].type == 8:  # Echo Request
            if hasattr(pkt[ICMP], 'id') and pkt[ICMP].id == 12345:
                paquetes_icmp.append(pkt)
    
    if not paquetes_icmp:
        print(f"{Colors.RED}No se encontraron paquetes ICMP con ID 12345{Colors.END}")
        return None
    
    # Ordenar por número de secuencia
    paquetes_icmp.sort(key=lambda p: p[ICMP].seq)
    
    # Extraer caracteres del payload
    mensaje_cifrado = ""
    print(f"{Colors.CYAN}Analizando {len(paquetes_icmp)} paquetes ICMP...{Colors.END}\n")
    
    for i, pkt in enumerate(paquetes_icmp):
        if hasattr(pkt[ICMP], 'load') and pkt[ICMP].load:
            # El primer byte del payload es el carácter
            char = chr(pkt[ICMP].load[0])
            mensaje_cifrado += char
            print(f"Paquete {pkt[ICMP].seq}: '{char}' (0x{pkt[ICMP].load[0]:02x})")
    
    if not mensaje_cifrado:
        print(f"{Colors.RED}No se pudo extraer ningún mensaje de los paquetes{Colors.END}")
        return None
    
    print(f"\n{Colors.YELLOW}Mensaje cifrado extraído: {Colors.BOLD}{mensaje_cifrado}{Colors.END}")
    return mensaje_cifrado

def descifrar_cesar(texto, corrimiento):
    """
    Descifra un texto usando el cifrado César con el corrimiento dado.
    """
    resultado = ""
    for char in texto:
        if char.isalpha():
            # Determinar si es mayúscula o minúscula
            base = ord('A') if char.isupper() else ord('a')
            # Aplicar el corrimiento hacia atrás (descifrado)
            char_descifrado = chr((ord(char) - base - corrimiento) % 26 + base)
            resultado += char_descifrado
        else:
            # No es letra, mantener igual
            resultado += char
    
    return resultado

def calcular_puntuacion_texto(texto):
    """
    Calcula una puntuación para determinar qué tan probable es que sea texto en español.
    Basado en frecuencia de letras comunes en español.
    """
    # Frecuencias aproximadas de letras en español (%)
    frecuencias_es = {
        'e': 13.68, 'a': 12.53, 'o': 8.68, 's': 7.98, 'r': 6.87,
        'n': 6.71, 'i': 6.25, 'd': 5.86, 'l': 4.97, 'c': 4.68,
        't': 4.63, 'u': 3.93, 'm': 3.15, 'p': 2.51, 'b': 2.22,
        'g': 2.01, 'v': 1.90, 'y': 1.54, 'q': 1.53, 'h': 1.18,
        'f': 1.08, 'z': 0.90, 'j': 0.52, 'ñ': 0.31, 'x': 0.22,
        'w': 0.02, 'k': 0.01
    }
    
    texto_lower = texto.lower()
    longitud = len([c for c in texto_lower if c.isalpha()])
    
    if longitud == 0:
        return 0
    
    puntuacion = 0
    for char in texto_lower:
        if char in frecuencias_es:
            puntuacion += frecuencias_es[char]
    
    # Bonificación por palabras comunes en español
    palabras_comunes = ['el', 'la', 'de', 'que', 'y', 'a', 'en', 'un', 'es', 'se', 
                       'no', 'te', 'lo', 'le', 'da', 'su', 'por', 'son', 'con', 'para',
                       'una', 'son', 'los', 'del', 'las', 'este', 'esta', 'como',
                       'pero', 'sus', 'ese', 'ser', 'han', 'mas', 'muy', 'bien']
    
    texto_palabras = re.findall(r'[a-záéíóúñ]+', texto_lower)
    for palabra in texto_palabras:
        if palabra in palabras_comunes:
            puntuacion += 10  # Bonificación por palabra común
    
    return puntuacion / longitud if longitud > 0 else 0

def probar_todas_las_claves(mensaje_cifrado):
    """
    Prueba todas las claves posibles del cifrado César (0-25) y muestra los resultados.
    Marca en verde la opción más probable.
    """
    print(f"\n{Colors.CYAN}{'='*60}")
    print(f"PROBANDO TODAS LAS CLAVES DEL CIFRADO CÉSAR")
    print(f"{'='*60}{Colors.END}\n")
    
    resultados = []
    
    for corrimiento in range(26):
        texto_descifrado = descifrar_cesar(mensaje_cifrado, corrimiento)
        puntuacion = calcular_puntuacion_texto(texto_descifrado)
        resultados.append((corrimiento, texto_descifrado, puntuacion))
    
    # Encontrar la puntuación máxima
    max_puntuacion = max(resultado[2] for resultado in resultados)
    
    # Mostrar todos los resultados
    for corrimiento, texto, puntuacion in resultados:
        if puntuacion == max_puntuacion:
            # Marcar en verde la opción más probable
            print(f"{Colors.GREEN}{Colors.BOLD}Clave {corrimiento:2d}: {texto} (Puntuación: {puntuacion:.2f}) ← MÁS PROBABLE{Colors.END}")
        else:
            print(f"Clave {corrimiento:2d}: {texto} (Puntuación: {puntuacion:.2f})")
    
    # Mostrar resumen
    mejor_resultado = max(resultados, key=lambda x: x[2])
    print(f"\n{Colors.GREEN}{Colors.BOLD}RESULTADO MÁS PROBABLE:{Colors.END}")
    print(f"{Colors.GREEN}Clave: {mejor_resultado[0]}")
    print(f"Mensaje: {mejor_resultado[1]}")
    print(f"Puntuación: {mejor_resultado[2]:.2f}{Colors.END}")

def main():
    if len(sys.argv) != 2:
        print(f"{Colors.RED}Uso: sudo python3 mitm.py captura.pcapng{Colors.END}")
        sys.exit(1)
    
    archivo_pcap = sys.argv[1]
    
    print(f"{Colors.CYAN}{Colors.BOLD}DECODIFICADOR DE MENSAJES ICMP CON CIFRADO CÉSAR{Colors.END}")
    print(f"{Colors.CYAN}Analizando archivo: {archivo_pcap}{Colors.END}\n")
    
    # Extraer mensaje cifrado
    mensaje_cifrado = extraer_mensaje_icmp(archivo_pcap)
    if not mensaje_cifrado:
        sys.exit(1)
    
    # Probar todas las claves César
    probar_todas_las_claves(mensaje_cifrado)

if __name__ == "__main__":
    main()