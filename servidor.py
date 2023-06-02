import socket
import threading
import rsa

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        self.clients = []
        self.public_keys = {}

    def broadcast(self, sender, message):
        for client in self.clients:
            if client != sender:
                client.send(message)

    def handle_client(self, client):
        while True:
            try:
                message = client.recv(1024)
                if message.decode().startswith('GET_PUB_KEY:'):
                    nickname = message.decode().split(':')[1]
                    self.handle_public_key_request(client, nickname)
                else:
                    self.broadcast(client, message)
            except:
                index = self.clients.index(client)
                self.clients.remove(client)
                client.close()
                nickname = list(self.public_keys.keys())[list(self.public_keys.values()).index(client)]
                del self.public_keys[nickname]
                self.broadcast(client, f'{nickname} left the chat!'.encode('utf-8'))
                break

    def handle_public_key_request(self, client, nickname):
        if nickname in self.public_keys:
            public_key = self.public_keys[nickname]
            client.send(public_key.save_pkcs1())
        else:
            client.send('ERROR: Chave publica nao encontrada'.encode('utf-8'))
            

    def receive_public_key(self, client):
        public_key = client.recv(1024)
        public_key = rsa.PublicKey.load_pkcs1(public_key)
        nickname = client.recv(1024).decode('utf-8')
        self.public_keys[nickname] = public_key
        print(f'Chave publica de {nickname} recebida!')
        return nickname

    def start(self):
        print('Servidor aguardando conexões')
        while True:
            client, address = self.server.accept()
            print(f'Conectado com {str(address)}')
            nickname = self.receive_public_key(client)
            self.clients.append(client)
            print(f'Nickname do client: {nickname}')
            thread = threading.Thread(target=self.handle_client, args=(client,))
            thread.start()

if __name__ == '__main__':
    server = Server('localhost', 5050)
    server.start()
