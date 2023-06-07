import socket
import threading
import rsa
import base64

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        self.clients = []
        self.public_keys = {}
        self.nicknames = {}

    def broadcast(self, sender, message):
        for client in self.clients:
            if client != sender:
                client.send(message)

    def handle_client(self, client):
        while True:
            # Receber o tamanho da mensagem criptografada em bytes
            encrypted_message_size_data = client.recv(4)
            encrypted_message_size = int.from_bytes(encrypted_message_size_data, byteorder='big')


            # Receber a mensagem criptografada
            encrypted_message = client.recv(encrypted_message_size)

            message = encrypted_message.decode('utf-8')
            if message.startswith('PUBLIC_KEY_REQUEST:'):
                # A mensagem é uma solicitação de chave pública
                sender_nickname = message.split(':', 1)[1]
                self.send_public_key(client, sender_nickname)
            else:
                if ':' in message:
                    # A mensagem contém um nome de usuário de destino
                    destination_nickname, message = message.split(':', 1)
                    print("destination_nickname:" + destination_nickname)

                    if destination_nickname in self.public_keys:

                        # Enviar o tamanho da mensagem criptografada em bytes
                        encrypted_message_size_data = len(encrypted_message).to_bytes(4, byteorder='big')

                        # Enviar a mensagem criptografada ao usuário de destino
                        destination_client = self.nicknames[destination_nickname]
                        destination_client.send(encrypted_message_size_data + encrypted_message)
                    else:
                        # Usuário de destino não encontrado
                        error_message = f'ERROR: Usuário {destination_nickname} não encontrado'
                        client.send(error_message.encode('utf-8'))
                else:
                    # A mensagem não contém um nome de usuário de destino
                    self.broadcast(client, message.encode('utf-8'))

    def send_public_key(self, client, sender_nickname):
        if sender_nickname in self.public_keys:
            # Enviar a chave pública do remetente ao cliente solicitante
            public_key_data = self.public_keys[sender_nickname].save_pkcs1()
            full_message_public_key = f'{sender_nickname}:{public_key_data}'

            public_key_size_data = len(full_message_public_key).to_bytes(4, byteorder='big')
            client.send(public_key_size_data + full_message_public_key.encode('utf-8'))
        else:
            # Remetente não encontrado
            error_message = f'ERROR: Usuário {sender_nickname} não encontrado'
            client.send(error_message.encode('utf-8'))

    def receive_public_key(self, client):
        # Receber o tamanho da chave pública em bytes
        public_key_size_data = client.recv(4)
        public_key_size = int.from_bytes(public_key_size_data, byteorder='big')

        # Receber a chave pública
        public_key_data = client.recv(public_key_size)
        public_key = rsa.PublicKey.load_pkcs1(public_key_data)

        # Receber o apelido
        nickname = client.recv(1024).decode('utf-8')
        self.public_keys[nickname] = public_key
        self.nicknames[nickname] = client
        print(f'Chave pública de {nickname} recebida!')
        return nickname

    def start(self):
        print('Servidor aguardando conexões')
        while True:
            client, address = self.server.accept()
            print(f'Conectado com {str(address)}')
            nickname = self.receive_public_key(client)
            self.clients.append(client)
            print(f'Nickname do cliente: {nickname}')
            thread = threading.Thread(target=self.handle_client, args=(client,))
            thread.start()


if __name__ == '__main__':
    server = Server('localhost', 5050)
    server.start()
