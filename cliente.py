import base64
import socket
import threading
import rsa


class Client:
    def __init__(self, host, port, nickname):
        self.host = host
        self.port = port
        self.nickname = nickname
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Gerar par de chaves RSA
        (self.public_key, self.private_key) = rsa.newkeys(2048)

        # Dicionário para armazenar as chaves públicas dos outros usuários
        self.other_public_keys = {}

    def connect(self):
        self.client.connect((self.host, self.port))

        # Enviar chave pública ao servidor
        public_key_data = self.public_key.save_pkcs1()
        public_key_size_data = len(public_key_data).to_bytes(4, byteorder='big')
        self.client.send(public_key_size_data + public_key_data)

        # Enviar apelido ao servidor
        self.client.send(self.nickname.encode('utf-8'))

    def send_message(self, message, _nickname):

            if _nickname in self.other_public_keys:
                public_key = self.other_public_keys[_nickname]
            else:
                 self.request_public_key(_nickname)
                 public_key = self.other_public_keys[_nickname]

            # Criptografar a mensagem usando a chave privada do cliente
            encrypted_message = rsa.encrypt(message.encode('utf-8'), public_key)

            full_message = f'{_nickname}:{encrypted_message}'

            # Enviar o tamanho da mensagem criptografada em bytes
            full_message_size_data = len(full_message).to_bytes(4, byteorder='big')

            self.client.send(full_message_size_data + full_message.encode('utf-8'))


    def request_public_key(self, sender_nickname):

        request_message = f'PUBLIC_KEY_REQUEST:{sender_nickname}'
        request_message_size_data = len(request_message).to_bytes(4, byteorder='big')
        self.client.send(request_message_size_data + request_message.encode('utf-8'))




    def receive_messages(self):
        while True:
            try:

                received_message_size_data = self.client.recv(4)
                received_message_size = int.from_bytes(received_message_size_data, byteorder='big')


                received_message = self.client.recv(received_message_size)
                str_received_message = received_message.decode('utf-8')

                print(str_received_message)
                if ':' in str_received_message:

                    sender_nickname, encrypted_message = str_received_message.split(':', 1)

                    if '-BEGIN RSA PUBLIC KEY-' in encrypted_message:


                        print(sender_nickname)
                        encrypted_message = encrypted_message[2:]
                        print(encrypted_message)

                        public_key = rsa.PublicKey.load_pkcs1(encrypted_message)
                        print(public_key)

                        # Armazenar a chave pública do remetente
                      #  self.other_public_keys[sender_nickname] = public_key
                    else:
                        decrypted_message = rsa.decrypt(encrypted_message.encode('utf-8'), self.private_key).decode('utf-8')
                        print(f'{decrypted_message}')
                else:
                    print(f"{'Usuario nao identificado. Falha'}")
            except rsa.DecryptionError:
                # Mensagem não criptografada ou criptografada com outra chave
                print('Mensagem nao criptograda ou chave invalida.')


if __name__ == '__main__':
    nickname = input('Digite seu apelido: ')
    client = Client('localhost', 5050, nickname)
    client.connect()

    thread = threading.Thread(target=client.receive_messages)
    thread.start()

    while True:
        destination_nickname = input('Digite o apelido do destinatário: ')
        message = input('Digite sua mensagem: ')
        print(message)

        #full_message = f'{destination_nickname}:{message}'
        client.send_message(message, nickname)
