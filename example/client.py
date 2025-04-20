# enhanced_client.py
import socket
import threading
import json
import os

class EnhancedClient:
    def __init__(self, host='127.0.0.1', port=5555):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))
        print(f"Connected to server at {host}:{port}")

    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode('utf-8')
                if not message:
                    break
                print(f"\nServer: {message}")
            except:
                break
        
        print("Disconnected from server")
        self.client_socket.close()

    def send_file(self, filepath):
        try:
            # Check if file exists
            if not os.path.exists(filepath):
                print(f"File {filepath} does not exist")
                return

            # Get file information
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)

            # Send file information
            file_info = {
                'type': 'file',
                'filename': filename,
                'filesize': filesize
            }
            self.client_socket.send(json.dumps(file_info).encode('utf-8'))

            # Wait for server ready signal
            if self.client_socket.recv(1024).decode('utf-8') == "READY":
                # Send file data
                with open(filepath, 'rb') as f:
                    while True:
                        data = f.read(4096)
                        if not data:
                            break
                        self.client_socket.send(data)
                print(f"File {filename} sent successfully")
            else:
                print("Server not ready to receive file")

        except Exception as e:
            print(f"Error sending file: {e}")

    def send_message(self, message):
        try:
            # Prepare message
            message_info = {
                'type': 'message',
                'content': message
            }
            self.client_socket.send(json.dumps(message_info).encode('utf-8'))
        except Exception as e:
            print(f"Error sending message: {e}")

    def start(self):
        # Start receiving messages in a separate thread
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.daemon = True
        receive_thread.start()

        # Main loop for sending messages
        while True:
            try:
                command = input("\nEnter command (message/file/quit): ").lower()
                
                if command == 'quit':
                    break
                elif command == 'file':
                    filepath = input("Enter file path: ")
                    self.send_file(filepath)
                elif command == 'message':
                    message = input("Enter message: ")
                    self.send_message(message)
                else:
                    print("Invalid command")
                    
            except KeyboardInterrupt:
                break

        self.client_socket.close()

if __name__ == "__main__":
    client = EnhancedClient()
    try:
        client.start()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print("Closing client...")