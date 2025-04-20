import socket
import threading
import signal
import sys
import time

class Server:
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = []
        self.running = False

    def setup_socket(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Add socket options to allow port reuse
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind and listen
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            print(f"[+] Server started successfully")
            print(f"[+] Listening on {self.host}:{self.port}")
            return True
            
        except Exception as e:
            print(f"[-] Error setting up server: {e}")
            self.cleanup()
            return False

    def handle_client(self, client_socket, addr):
        print(f"[+] New connection from {addr}")
        
        while self.running:
            try:
                message = client_socket.recv(1024).decode('utf-8')
                if not message:
                    break
                
                print(f"[+] Message from {addr}: {message}")
                response = f"Server received: {message}"
                client_socket.send(response.encode('utf-8'))
                
            except Exception as e:
                print(f"[-] Error handling client {addr}: {e}")
                break
        
        print(f"[-] Connection closed from {addr}")
        if client_socket in self.clients:
            self.clients.remove(client_socket)
        client_socket.close()

    def start(self):
        if not self.setup_socket():
            return

        self.running = True
        print("[*] Server is waiting for connections...")
        
        while self.running:
            try:
                self.server_socket.settimeout(1.0)  # Add timeout to allow checking running flag
                try:
                    client_socket, addr = self.server_socket.accept()
                    self.clients.append(client_socket)
                    
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, addr)
                    )
                    client_thread.daemon = True  # Make thread daemon so it closes with main thread
                    client_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:  # Only show error if we're still meant to be running
                        print(f"[-] Error accepting connection: {e}")
                    break
                    
            except KeyboardInterrupt:
                break

    def cleanup(self):
        print("\n[*] Cleaning up server...")
        self.running = False
        
        # Close all client connections
        for client in self.clients[:]:  # Use slice copy to avoid modification during iteration
            try:
                client.close()
                self.clients.remove(client)
            except:
                pass
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None
        
        print("[+] Cleanup completed")

def signal_handler(signum, frame):
    print("\n[*] Signal received, shutting down...")
    if server:
        server.cleanup()
    sys.exit(0)

if __name__ == "__main__":
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    server = Server()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[*] Keyboard interrupt received")
    finally:
        server.cleanup()