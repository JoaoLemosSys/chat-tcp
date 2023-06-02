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

    def connect(self):
        self.client.connect((self.host, self.port))

        # Enviar chave pública ao servidor
        public_key_data = self.public_key.save_pkcs1()
        public_key_size_data = len(public_key_data).to_bytes(4, byteorder='big')
        self.client.send(public_key_size_data + public_key_data)

        # Enviar apelido ao servidor
        self.client.send(self.nickname.encode('utf-8'))

    def send_message(self, message):

        tamanho_da_messagem = len(message).to_bytes(4, byteorder='big')
        self.client.send(tamanho_da_messagem+message.encode('utf-8'))

    def receive_messages(self):
        while True:
            # Receber o tamanho da mensagem criptografada em bytes
            encrypted_message_size_data = self.client.recv(4)
            print(encrypted_message_size_data.decode())
            encrypted_message_size = int.from_bytes(encrypted_message_size_data, byteorder='big')

            # Receber a mensagem criptografada

            encrypted_message = self.client.recv(encrypted_message_size)


            try:
                # Tentar descriptografar a mensagem usando a chave privada
                decrypted_message = rsa.decrypt(encrypted_message, self.private_key).decode('utf-8')
                print(f'{decrypted_message}')
            except rsa.DecryptionError:
                # Mensagem não criptografada ou criptografada com outra chave
                print(f'{encrypted_message.decode("utf-8")}')


if __name__ == '__main__':
    nickname = input('Digite seu apelido: ')
    client = Client('localhost', 5050, nickname)
    client.connect()

    thread = threading.Thread(target=client.receive_messages)
    thread.start()

    while True:
        destination_nickname = input('Digite o apelido do destinatário: ')
        message = input('Digite sua mensagem: ')

        full_message = f'{destination_nickname}:{message}'
        client.send_message(full_message)
