from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii


def ajustar_clave(clave, tamanio_requerido, nombre_algoritmo):
    """
    Ajusta la clave al tamaño requerido.
    - Si es menor, completa con bytes aleatorios
    - Si es mayor, trunca la clave
    """
    clave_bytes = clave.encode('utf-8')
    longitud_actual = len(clave_bytes)
    
    if longitud_actual < tamanio_requerido:
        # Completar con bytes aleatorios
        bytes_faltantes = tamanio_requerido - longitud_actual
        clave_ajustada = clave_bytes + get_random_bytes(bytes_faltantes)
        print(f"\n[{nombre_algoritmo}] Clave menor al tamaño requerido.")
        print(f"  -> Se agregaron {bytes_faltantes} bytes aleatorios.")
    elif longitud_actual > tamanio_requerido:
        # Truncar la clave
        clave_ajustada = clave_bytes[:tamanio_requerido]
        print(f"\n[{nombre_algoritmo}] Clave mayor al tamaño requerido.")
        print(f"  -> Se truncó a {tamanio_requerido} bytes.")
    else:
        clave_ajustada = clave_bytes
        print(f"\n[{nombre_algoritmo}] Clave del tamaño correcto.")
    
    return clave_ajustada


def ajustar_iv(iv, tamanio_requerido, nombre_algoritmo):
    """
    Ajusta el IV al tamaño requerido del bloque.
    """
    iv_bytes = iv.encode('utf-8')
    longitud_actual = len(iv_bytes)
    
    if longitud_actual < tamanio_requerido:
        bytes_faltantes = tamanio_requerido - longitud_actual
        iv_ajustado = iv_bytes + get_random_bytes(bytes_faltantes)
        print(f"[{nombre_algoritmo}] IV completado con {bytes_faltantes} bytes aleatorios.")
    elif longitud_actual > tamanio_requerido:
        iv_ajustado = iv_bytes[:tamanio_requerido]
        print(f"[{nombre_algoritmo}] IV truncado a {tamanio_requerido} bytes.")
    else:
        iv_ajustado = iv_bytes
    
    return iv_ajustado


def cifrar_des(clave, iv, texto):
    """
    Cifra un texto usando DES en modo CBC.
    DES requiere clave de 8 bytes y bloque de 8 bytes.
    """
    print("\n" + "="*60)
    print("ALGORITMO: DES (Data Encryption Standard)")
    print("="*60)
    
    # Ajustar clave e IV
    clave_ajustada = ajustar_clave(clave, 8, "DES")
    iv_ajustado = ajustar_iv(iv, 8, "DES")
    
    print(f"\nClave final (hex): {binascii.hexlify(clave_ajustada).decode()}")
    print(f"IV final (hex): {binascii.hexlify(iv_ajustado).decode()}")
    
    # Crear cipher
    cipher = DES.new(clave_ajustada, DES.MODE_CBC, iv_ajustado)
    
    # Cifrar
    texto_bytes = texto.encode('utf-8')
    texto_padded = pad(texto_bytes, DES.block_size)
    texto_cifrado = cipher.encrypt(texto_padded)
    
    print(f"\nTexto original: {texto}")
    print(f"Texto cifrado (hex): {binascii.hexlify(texto_cifrado).decode()}")
    
    return texto_cifrado, clave_ajustada, iv_ajustado


def descifrar_des(clave, iv, texto_cifrado):
    """
    Descifra un texto usando DES en modo CBC.
    """
    cipher = DES.new(clave, DES.MODE_CBC, iv)
    texto_descifrado = unpad(cipher.decrypt(texto_cifrado), DES.block_size)
    texto_descifrado_str = texto_descifrado.decode('utf-8')
    
    print(f"Texto descifrado: {texto_descifrado_str}")
    print("="*60)
    
    return texto_descifrado_str


def cifrar_3des(clave, iv, texto):
    """
    Cifra un texto usando 3DES en modo CBC.
    3DES requiere clave de 16 o 24 bytes y bloque de 8 bytes.
    Usaremos 24 bytes (3DES con 3 claves).
    """
    print("\n" + "="*60)
    print("ALGORITMO: 3DES (Triple DES)")
    print("="*60)
    
    # Ajustar clave e IV
    clave_ajustada = ajustar_clave(clave, 24, "3DES")
    iv_ajustado = ajustar_iv(iv, 8, "3DES")
    
    print(f"\nClave final (hex): {binascii.hexlify(clave_ajustada).decode()}")
    print(f"IV final (hex): {binascii.hexlify(iv_ajustado).decode()}")
    
    # Crear cipher
    cipher = DES3.new(clave_ajustada, DES3.MODE_CBC, iv_ajustado)
    
    # Cifrar
    texto_bytes = texto.encode('utf-8')
    texto_padded = pad(texto_bytes, DES3.block_size)
    texto_cifrado = cipher.encrypt(texto_padded)
    
    print(f"\nTexto original: {texto}")
    print(f"Texto cifrado (hex): {binascii.hexlify(texto_cifrado).decode()}")
    
    return texto_cifrado, clave_ajustada, iv_ajustado


def descifrar_3des(clave, iv, texto_cifrado):
    """
    Descifra un texto usando 3DES en modo CBC.
    """
    cipher = DES3.new(clave, DES3.MODE_CBC, iv)
    texto_descifrado = unpad(cipher.decrypt(texto_cifrado), DES3.block_size)
    texto_descifrado_str = texto_descifrado.decode('utf-8')
    
    print(f"Texto descifrado: {texto_descifrado_str}")
    print("="*60)
    
    return texto_descifrado_str


def cifrar_aes256(clave, iv, texto):
    """
    Cifra un texto usando AES-256 en modo CBC.
    AES-256 requiere clave de 32 bytes y bloque de 16 bytes.
    """
    print("\n" + "="*60)
    print("ALGORITMO: AES-256 (Advanced Encryption Standard)")
    print("="*60)
    
    # Ajustar clave e IV
    clave_ajustada = ajustar_clave(clave, 32, "AES-256")
    iv_ajustado = ajustar_iv(iv, 16, "AES-256")
    
    print(f"\nClave final (hex): {binascii.hexlify(clave_ajustada).decode()}")
    print(f"IV final (hex): {binascii.hexlify(iv_ajustado).decode()}")
    
    # Crear cipher
    cipher = AES.new(clave_ajustada, AES.MODE_CBC, iv_ajustado)
    
    # Cifrar
    texto_bytes = texto.encode('utf-8')
    texto_padded = pad(texto_bytes, AES.block_size)
    texto_cifrado = cipher.encrypt(texto_padded)
    
    print(f"\nTexto original: {texto}")
    print(f"Texto cifrado (hex): {binascii.hexlify(texto_cifrado).decode()}")
    
    return texto_cifrado, clave_ajustada, iv_ajustado


def descifrar_aes256(clave, iv, texto_cifrado):
    """
    Descifra un texto usando AES-256 en modo CBC.
    """
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    texto_descifrado = unpad(cipher.decrypt(texto_cifrado), AES.block_size)
    texto_descifrado_str = texto_descifrado.decode('utf-8')
    
    print(f"Texto descifrado: {texto_descifrado_str}")
    print("="*60)
    
    return texto_descifrado_str


def main():
    """
    Función principal del programa.
    """
    print("\nAlgoritmos: DES, 3DES, AES-256")
    print("Modo: CBC (Cipher Block Chaining)")
    print("="*60)
    
    # Solicitar datos al usuario
    print("\n--- ENTRADA DE DATOS ---")
    clave_des = input("\nIngrese la clave para DES: ")
    iv_des = input("Ingrese el IV para DES: ")
    
    clave_3des = input("\nIngrese la clave para 3DES: ")
    iv_3des = input("Ingrese el IV para 3DES: ")
    
    clave_aes = input("\nIngrese la clave para AES-256: ")
    iv_aes = input("Ingrese el IV para AES-256: ")
    
    texto = input("\nIngrese el texto a cifrar: ")
    
    # DES
    texto_cifrado_des, clave_final_des, iv_final_des = cifrar_des(clave_des, iv_des, texto)
    descifrar_des(clave_final_des, iv_final_des, texto_cifrado_des)
    
    # 3DES
    texto_cifrado_3des, clave_final_3des, iv_final_3des = cifrar_3des(clave_3des, iv_3des, texto)
    descifrar_3des(clave_final_3des, iv_final_3des, texto_cifrado_3des)
    
    # AES-256
    texto_cifrado_aes, clave_final_aes, iv_final_aes = cifrar_aes256(clave_aes, iv_aes, texto)
    descifrar_aes256(clave_final_aes, iv_final_aes, texto_cifrado_aes)

if __name__ == "__main__":
    main()