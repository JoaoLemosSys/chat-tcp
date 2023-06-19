import socket
import threading
import rsa

class Server:
    def __init__(self, host, port):
        # Inicializa o servidor com o endereço e a porta especificados
        self.host = host
        self.port = port
        # Cria um novo objeto de soquete para o servidor
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Associa o soquete ao endereço e à porta especificados
        self.server.bind((self.host, self.port))
        # Coloca o servidor em modo de escuta para aceitar conexões de entrada
        self.server.listen(5)
        # Inicializa uma lista vazia para armazenar os clientes conectados
        self.clients = []
        # Inicializa um dicionário vazio para armazenar as chaves públicas dos clientes
        self.public_keys = {}
        # Inicializa um dicionário vazio para armazenar os apelidos dos clientes
        self.nicknames = {}

    def handle_client(self, client, nickname_client):
        while True:
            # Recebe o tamanho da mensagem criptografada em bytes do cliente
            encrypted_message_size_data = client.recv(4)
            encrypted_message_size = int.from_bytes(encrypted_message_size_data, byteorder='big')

            # Recebe a mensagem criptografada do cliente
            encrypted_message = client.recv(encrypted_message_size)

            # Decodifica a mensagem criptografada
            message = encrypted_message.decode('utf-8')
            if message.startswith('PUBLIC_KEY_REQUEST:'):
                # A mensagem é uma solicitação de chave pública de outro usuário
                nickname_key_requested = message.split(':', 1)[1]
                # Envia a chave pública do usuário solicitado ao cliente
                self.send_public_key(client, nickname_key_requested)
                print(f"Solicitando chave publica de {nickname_client}")
            else:
                if ':' in message:
                    # A mensagem contém um nome de usuário de destino
                    destination_nickname, message = message.split(':', 1)

                    if destination_nickname in self.public_keys:
                        # O usuário de destino está conectado ao servidor

                        # Envia o tamanho da mensagem criptografada em bytes ao usuário de destino
                        encrypted_message_size_data = len(encrypted_message).to_bytes(4, byteorder='big')

                        # Envia a mensagem criptografada ao usuário de destino
                        destination_client = self.nicknames[destination_nickname]
                        destination_client.send(encrypted_message_size_data + encrypted_message)
                    else:
                        # Usuário de destino não encontrado ou não conectado ao servidor
                        error_message = f'ERROR: Usuário {destination_nickname} não encontrado'
                        client.send(error_message.encode('utf-8'))
                else:
                    # A mensagem não contém um nome de usuário de destino e deve ser transmitida para todos os usuários conectados
                    self.broadcast(client, message.encode('utf-8'))


    def send_public_key(self, client, nickname_key_requested):
        if nickname_key_requested in self.public_keys:
            # Envia a chave pública do remetente ao cliente solicitante
            print(f"Enviando chave de {nickname_key_requested}")
            public_key_data = self.public_keys[nickname_key_requested].save_pkcs1()
            full_message_public_key = f'{nickname_key_requested}:{public_key_data}'

            public_key_size_data = len(full_message_public_key).to_bytes(4, byteorder='big')
            client.send(public_key_size_data + full_message_public_key.encode('utf-8'))
        else:
            # Remetente não encontrado
            error_message = f'ERROR: Usuário {nickname_key_requested} não encontrado'
            client.send(error_message.encode('utf-8'))

    def receive_public_key(self, client):
        # Recebe o tamanho da chave pública em bytes do cliente
        public_key_size_data = client.recv(4)
        public_key_size = int.from_bytes(public_key_size_data, byteorder='big')

        # Recebe a chave pública do cliente
        public_key_data = client.recv(public_key_size)
        public_key = rsa.PublicKey.load_pkcs1(public_key_data)

        # Recebe o apelido do cliente
        nickname = client.recv(1024).decode('utf-8')
        # Armazena a chave pública e o objeto de soquete do cliente nos dicionários apropriados
        self.public_keys[nickname] = public_key
        self.nicknames[nickname] = client
        print(f'Chave pública de {nickname} recebida e armazenada!')
        return nickname

    def broadcast(self, sender_client, message):
        # Envia a mensagem para todos os clientes conectados, exceto o remetente
        for client in self.clients:
            if client != sender_client:
                client.send(message)
    
def start(self):
    # Coloca o servidor em modo de escuta para aceitar conexões de entrada
    print('Servidor aguardando conexões')
    while True:
        # Aceita uma nova conexão de entrada
        client, address = self.server.accept()
        print(f'Conectado com {str(address)}')
        # Recebe a chave pública e o apelido do cliente
        nickname = self.receive_public_key(client)
        # Adiciona o objeto de soquete do cliente à lista de clientes conectados
        self.clients.append(client)
        print(f'Nickname do cliente: {nickname}')
        # Inicia uma nova thread para lidar com as mensagens recebidas do cliente
        thread = threading.Thread(target=self.handle_client, args=(client, nickname))
        thread.start()


if __name__ == '__main__':
    # Cria uma instância da classe Server e inicia o servidor
    server = Server('localhost', 5050)
    server.start()
