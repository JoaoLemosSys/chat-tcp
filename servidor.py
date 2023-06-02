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

            # Descriptografar a mensagem usando a chave privada
            message = encrypted_message.decode('utf-8')
            print("message:" + message)

            if ':' in message:
                # A mensagem contém um nome de usuário de destino
                destination_nickname, message = message.split(':', 1)
                print("destination_nickname:" + destination_nickname)

                if destination_nickname in self.public_keys:
                    print("achou a chave")
                    # Criptografar a mensagem usando a chave pública do usuário de destino
                    public_key = self.public_keys[destination_nickname]
                    encrypted_message = rsa.encrypt(message.encode('utf-8'), public_key)

                    # Enviar o tamanho da mensagem criptografada em bytes
                    encrypted_message_size_data = len(encrypted_message).to_bytes(4, byteorder='big')
                    print("tamanho da mensagem enviada")
                    print(encrypted_message_size_data)

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