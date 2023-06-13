import socket
import sys
import threading
import rsa


class Client:
    def __init__(self, host, port, nickname):
        self.host = host
        self.port = port
        self.nickname = nickname
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        (self.public_key, self.private_key) = rsa.newkeys(256)
        self.other_public_keys = {}

    def connect(self):
        self.client.connect((self.host, self.port))

        public_key_data = self.public_key.save_pkcs1()
        public_key_size_data = len(public_key_data).to_bytes(4, byteorder='big')
        self.client.send(public_key_size_data + public_key_data)

        self.client.send(self.nickname.encode('utf-8'))

    def disconnect(self):
        self.client.close()

    def send_message(self, message, destination_nickname):
        pb = ""
        try:
            if destination_nickname in self.other_public_keys:
                public_key = self.other_public_keys[destination_nickname]
                pb = public_key.save_pkcs1()
            else:
                self.request_public_key(destination_nickname)
                public_key = self.other_public_keys[destination_nickname]
                pb = public_key.save_pkcs1()

            encrypted_message = rsa.encrypt(message.encode('utf-8'), public_key)
            full_message = f'{destination_nickname}:{encrypted_message}'
            full_message_size_data = len(full_message).to_bytes(4, byteorder='big')

            self.client.send(full_message_size_data + full_message.encode('utf-8'))

        except Exception as e:
            print(e)

    def request_public_key(self, destination_nickname):

        request_message = f'PUBLIC_KEY_REQUEST:{destination_nickname}'
        request_message_size_data = len(request_message).to_bytes(4, byteorder='big')
        self.client.send(request_message_size_data + request_message.encode('utf-8'))

    def receive_messages(self):
        while True:
            try:

                received_message_size_data = self.client.recv(4)
                received_message_size = int.from_bytes(received_message_size_data, byteorder='big')

                received_message = self.client.recv(received_message_size)
                str_received_message = received_message.decode('unicode_escape')

                if ':' in str_received_message:

                    nickname_requested, encrypted_message = str_received_message.split(':', 1)

                    if '-BEGIN RSA PUBLIC KEY-' in encrypted_message:

                        encrypted_message = encrypted_message[2:]
                        public_key = rsa.PublicKey.load_pkcs1(encrypted_message)
                        self.other_public_keys[nickname_requested] = public_key
                    else:
                        sender_nickname = nickname_requested
                        decrypted_message = rsa.decrypt(encrypted_message.encode('utf-8'), self.private_key).decode('utf-8')
                        print(f'Mensagem recebida de {sender_nickname}: {decrypted_message}')
                else:
                    print(f"{'Usuario nao identificado. Falha'}")
            except rsa.DecryptionError as e:
                print('\nMensagem recebida nao pode ser descriptograda.\n')


if __name__ == '__main__':
    nickname = input('Digite seu apelido: ')
    client = Client('localhost', 5050, nickname)
    client.connect()

    receive_thread = threading.Thread(target=client.receive_messages)
    receive_thread.start()

    while True:
        destination_nickname = input('Digite o apelido do destinatário:')
        message = input("Digite sua mensagem ou 'sair' para finalizar:")

        if message.lower() == "sair":
            client.disconnect()
            receive_thread.join()
            break

        send_thread = threading.Thread(target=client.send_message, args=(message, destination_nickname))
        send_thread.start()

