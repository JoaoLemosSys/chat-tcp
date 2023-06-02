import socket
import threading
import rsa

class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))
        (self.public_key, self.private_key) = rsa.newkeys(2048)

    def send_message(self):
        while True:
            message = input('')
            usernameDestinatario = input('Digite o nome do destinatario: ')
            self.client.send(f'GET_PUB_KEY:{usernameDestinatario}'.encode('utf-8'))
            public_key_destinatario = rsa.PublicKey.load_pkcs1(self.client.recv(1024))
            encrypted_message = rsa.encrypt(message.encode('utf-8'), public_key_destinatario)
            self.client.send(encrypted_message)

    def receive_message(self):
        while True:
            try:
                message = self.client.recv(1024 )
                if not message.startswith('GET_PUBLIC_KEY:'):
                    decrypted_message = rsa.decrypt(message, self.private_key).decode('utf-8')
                    print(decrypted_message)
            except:
                print('An error occurred!')
                self.client.close()
                break

    def start(self):
        nickname = input('Digite seu nome de usuario: ')
        self.client.send(self.public_key.save_pkcs1())
        self.client.send(nickname.encode('utf-8'))
        receive_thread = threading.Thread(target=self.receive_message)
        receive_thread.start()
        send_thread = threading.Thread(target=self.send_message)
        send_thread.start()

if __name__ == '__main__':
    client = Client('localhost', 5050)
    client.start()
