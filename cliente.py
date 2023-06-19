import base64
import socket
import sys
import threading
import rsa

# Define a classe Cliente para um cliente de chat
class Client:
    # Inicializa o cliente com host, porta e apelido
    def __init__(self, host, port, nickname):
        self.host = host
        self.port = port
        self.nickname = nickname
        # Cria um objeto de soquete para se conectar ao servidor
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Gera um par de chaves pública/privada para criptografia RSA
        (self.public_key, self.private_key) = rsa.newkeys(256)
        # Dicionário para armazenar chaves públicas de outros usuários
        self.other_public_keys = {}

    # Conecta o cliente ao servidor
    def connect(self):
        self.client.connect((self.host, self.port))

        # Envia a chave pública do cliente para o servidor
        public_key_data = self.public_key.save_pkcs1()
        public_key_size_data = len(public_key_data).to_bytes(4, byteorder='big')
        self.client.send(public_key_size_data + public_key_data)

        # Envia o apelido do cliente para o servidor
        self.client.send(self.nickname.encode('utf-8'))

    # Desconecta o cliente do servidor
    def disconnect(self):
        self.client.close()

    # Envia uma mensagem criptografada para outro usuário
    def send_message(self, message, destination_nickname):
        try:
            # Verifica se a chave pública do destinatário já foi recebida
            if destination_nickname in self.other_public_keys:
                public_key = self.other_public_keys[destination_nickname]
            else:
                # Se a chave pública do destinatário ainda não foi recebida, solicita a chave pública do destinatário
                print(f'\nNão foi possivel enviar mensagem para {destination_nickname}.\nUsuario ainda não possui chave cadastrada. Solicitando chave... \n')
                self.request_public_key(destination_nickname)
                public_key = self.other_public_keys[destination_nickname]

            # Criptografa a mensagem com a chave pública do destinatário
            encrypted_message = rsa.encrypt(message.encode('utf-8'), public_key)
            encoded_ciphertext = base64.b64encode(encrypted_message).decode('utf-8')

            # Envia a mensagem criptografada para o servidor com o apelido do destinatário
            full_message = f'{destination_nickname}:{encoded_ciphertext}'
            full_message_size_data = len(full_message).to_bytes(4, byteorder='big')

            self.client.send(full_message_size_data + full_message.encode('utf-8'))

        except Exception as e:
            print(e)

    # Solicita a chave pública de outro usuário ao servidor
    def request_public_key(self, destination_nickname):
        request_message = f'PUBLIC_KEY_REQUEST:{destination_nickname}'
        request_message_size_data = len(request_message).to_bytes(4, byteorder='big')
        self.client.send(request_message_size_data + request_message.encode('utf-8'))

    # Recebe mensagens do servidor e as descriptografa se necessário
    def receive_messages(self):
        # Recebe as mensagens continuamente
        while True:
            try:
                received_message_size_data = self.client.recv(4)
                received_message_size = int.from_bytes(received_message_size_data, byteorder='big')
                # Recebe a mensagem do servidor com o tamanho especificado
                received_message = self.client.recv(received_message_size)
                
                # Decodifica a mensagem recebida
                str_received_message = received_message.decode('unicode_escape')

                if ':' in str_received_message:
                
                    # Separa a mensagem recebida em apelido e mensagem criptografada
                    nickname_requested, encrypted_message = str_received_message.split(':', 1)

                    # Se a mensagem contém a string '-BEGIN RSA PUBLIC KEY-' está recebendo uma chave publica solicitada
                    if '-BEGIN RSA PUBLIC KEY-' in encrypted_message:                        
                        # Carrega a chave pública do usuário que enviou a mensagem e
                        # Armazena a chave pública do usuário que enviou a mensagem no dicionário de chaves públicas
                        encrypted_message = encrypted_message[2:]                        
                        public_key = rsa.PublicKey.load_pkcs1(encrypted_message)
                        self.other_public_keys[nickname_requested] = public_key
                        print(f'\nChave Pública de {nickname_requested} recebida.\n Pronto para enviar mensagens para {nickname_requested}.\n')
                    else:
                                            # Se a mensagem criptografada não contém a string '-BEGIN RSA PUBLIC KEY-', então é uma mensagem criptografada normal
                        sender_nickname = nickname_requested
                        # Decodifica a mensagem criptografada usando base64
                        encrypted_message = base64.b64decode(encrypted_message.encode('utf-8'))
                        # Descriptografa a mensagem usando a chave privada do cliente
                        decrypted_message = rsa.decrypt(encrypted_message, self.private_key).decode('utf-8')
                        # Imprime a mensagem descriptografada
                        print(f'\nMensagem recebida: {decrypted_message}')
                else:
                    print(f"{'Usuario nao identificado. Falha'}")
            except rsa.DecryptionError as e:
                print('\nMensagem recebida nao pode ser descriptograda.\n')


if __name__ == '__main__':
    # Solicita ao usuário que insira seu apelido
    nickname = input('Digite seu apelido: ')
    # Cria um novo objeto cliente com o apelido fornecido
    client = Client('localhost', 5050, nickname)
    # Conecta o cliente ao servidor
    client.connect()

    # Inicia uma nova thread para receber mensagens do servidor
    receive_thread = threading.Thread(target=client.receive_messages)
    receive_thread.start()

    # Continuamente solicita ao usuário que insira um apelido de destino e uma mensagem
    while True:
        destination_nickname = input('Digite o apelido do destinatário:')
        message = input("Digite sua mensagem ou 'sair' para finalizar:")

        # Se a mensagem for "sair", desconecta o cliente e encerra a thread de recebimento de mensagens
        if message.lower() == "sair":
            client.disconnect()
            receive_thread.join()
            break

        # Inicia uma nova thread para enviar a mensagem para o destinatário especificado
        send_thread = threading.Thread(target=client.send_message, args=(message, destination_nickname))
        send_thread.start()
