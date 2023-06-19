import base64
import socket
import sys
import threading
import rsa

class Client:
    def __init__(self, host, port, nickname):
        self.host = host  # Endereço IP do servidor de chat
        self.port = port  # Porta do servidor de chat
        self.nickname = nickname  # Apelido do usuário
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Cria um objeto de soquete para se conectar ao servidor
        (self.public_key, self.private_key) = rsa.newkeys(256)  # Gera um par de chaves pública/privada RSA
        self.other_public_keys = {}  # Armazena as chaves públicas de outros usuários

    def connect(self):
        self.client.connect((self.host, self.port))  # Conecta-se ao servidor de chat

        public_key_data = self.public_key.save_pkcs1()  # Salva a chave pública em formato PKCS1
        public_key_size_data = len(public_key_data).to_bytes(4, byteorder='big')  # Obtém o tamanho da chave pública em bytes
        self.client.send(public_key_size_data + public_key_data)  # Envia o tamanho e a chave pública para o servidor

        self.client.send(self.nickname.encode('utf-8'))  # Envia o apelido para o servidor

    def disconnect(self):
        self.client.close()  # Fecha a conexão com o servidor

    def send_message(self, message, destination_nickname):
        try:
            if destination_nickname in self.other_public_keys:
                public_key = self.other_public_keys[destination_nickname]  # Obtém a chave pública do destinatário se já estiver armazenada localmente
            else:
                print(f'\nNão foi possivel enviar mensagem para {destination_nickname}.\nUsuario ainda não possui chave cadastrada. Solicitando chave... \n')
                self.request_public_key(destination_nickname)  # Solicita a chave pública do destinatário ao servidor se ainda não estiver armazenada localmente
                public_key = self.other_public_keys[destination_nickname]

            encrypted_message = rsa.encrypt(message.encode('utf-8'), public_key)  # Criptografa a mensagem usando a chave pública do destinatário
            encoded_ciphertext = base64.b64encode(encrypted_message).decode('utf-8')  # Codifica a mensagem criptografada em base64

            full_message = f'{destination_nickname}:{encoded_ciphertext}'  # Formata a mensagem completa com o apelido do destinatário e a mensagem criptografada
            full_message_size_data = len(full_message).to_bytes(4, byteorder='big')  # Obtém o tamanho da mensagem completa em bytes

            self.client.send(full_message_size_data + full_message.encode('utf-8'))  # Envia o tamanho e a mensagem completa para o servidor

        except Exception as e:
            print(e)

    def request_public_key(self, destination_nickname):
        request_message = f'PUBLIC_KEY_REQUEST:{destination_nickname}'  # Formata a mensagem de solicitação de chave pública com o apelido do destinatário
        request_message_size_data = len(request_message).to_bytes(4, byteorder='big')  # Obtém o tamanho da mensagem de solicitação em bytes
        self.client.send(request_message_size_data + request_message.encode('utf-8'))  # Envia o tamanho e a mensagem de solicitação para o servidor

    def receive_messages(self):
        while True:
            try:
                received_message_size_data = self.client.recv(4)  # Recebe o tamanho da mensagem recebida do servidor em bytes
                received_message_size = int.from_bytes(received_message_size_data, byteorder='big')  # Converte o tamanho da mensagem recebida para um inteiro

                received_message = self.client.recv(received_message_size)  # Recebe a mensagem completa do servidor
                str_received_message = received_message.decode('unicode_escape')

                if ':' in str_received_message:
                    nickname_requested, encrypted_message = str_received_message.split(':', 1)  # Separa o apelido do remetente e a mensagem criptografada

                    if '-BEGIN RSA PUBLIC KEY-' in encrypted_message:                        
                        encrypted_message = encrypted_message[2:]
                        public_key = rsa.PublicKey.load_pkcs1(encrypted_message)  # Carrega a chave pública do remetente em formato PKCS1
                        self.other_public_keys[nickname_requested] = public_key  # Armazena a chave pública do remetente localmente
                        print(f'\nChave Pública de {nickname_requested} recebida.\n Pronto para enviar mensagens para {nickname_requested}.\n')
                    else:
                        sender_nickname = nickname_requested
                        encrypted_message = base64.b64decode(encrypted_message.encode('utf-8'))  # Decodifica a mensagem criptografada de base64
                        decrypted_message = rsa.decrypt(encrypted_message, self.private_key).decode('utf-8')  # Descriptografa a mensagem usando a chave privada do usuário
                        print(f'\nMensagem recebida: {decrypted_message}')
                else:
                    print(f"{'Usuario nao identificado. Falha'}")
            except rsa.DecryptionError as e:
                print('\nMensagem recebida nao pode ser descriptograda.\n')

if __name__ == '__main__':
    nickname = input('Digite seu apelido: ')  # Pede ao usuário para digitar seu apelido
    client = Client('localhost', 5050, nickname)  # Cria um objeto de cliente com o endereço IP e a porta do servidor e o apelido do usuário
    client.connect()  # Conecta-se ao servidor de chat

    receive_thread = threading.Thread(target=client.receive_messages)  # Cria uma thread para receber mensagens do servidor
    receive_thread.start()  # Inicia a thread de recebimento de mensagens

    while True:
        destination_nickname = input('Digite o apelido do destinatário:')  # Pede ao usuário para digitar o apelido do destinatário
        message = input("Digite sua mensagem ou 'sair' para finalizar:")  # Pede ao usuário para digitar sua mensagem ou 'sair' para finalizar

        if message.lower() == "sair":  # Se o usuário digitar 'sair'
            client.disconnect()  # Desconecta-se do servidor
            receive_thread.join()  # Aguarda a thread de recebimento de mensagens finalizar
            break  # Sai do loop

        send_thread = threading.Thread(target=client.send_message, args=(message, destination_nickname))  # Cria uma thread para enviar a mensagem para o destinatário
        send_thread.start()  # Inicia a thread de envio de mensagens
