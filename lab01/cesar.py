import sys

def cifrado_cesar(texto: str, corrimiento: int) -> str:
    resultado = ""
    for char in texto:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            resultado += chr((ord(char) - base + corrimiento) % 26 + base)
        else:
            resultado += char
    return resultado


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py \"<texto>\" <corrimiento>")
        sys.exit(1)

    mensaje = sys.argv[1]
    try:
        corrimiento = int(sys.argv[2])
    except ValueError:
        print("El corrimiento debe ser un número entero.")
        sys.exit(1)

    cifrado = cifrado_cesar(mensaje, corrimiento)
    print(f"Texto original : {mensaje}")
    print(f"Corrimiento    : {corrimiento}")
    print(f"Texto cifrado  : {cifrado}")