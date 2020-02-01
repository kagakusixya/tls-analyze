import random
import socket
from time import sleep


class TLS_Analyze:
    def __init__(self):
        self.Define()

    def Define(self):
        self.content_type = {"change_cipher_spec": b'\x14', "alert": b'\x15',
                             "handshake": b'\x16', "application_data": b'\x17'}
        self.protocol_version = {"TLS1.0": b'\x03\x01', "TLS1.2": b'\x03\x03'}

    def TLS_Record_Layer(self):
        self.content_type = self.content_type["handshake"]
        self.version = self.protocol_version["TLS1.0"]
        self.length = b'\x00\x00'

    def TLS_Record_Layer_byte(self):
        byte_data = self.content_type + self.version + self.length
        return byte_data

    def Handshake_Header(self):
        self.handshake_type = b'\x01'
        self.handshak_length = b'\x00\x00\x00'

    def Handshake_Header_byte(self):
        byte_data = self.handshake_type + self.handshak_length
        return byte_data

    def Handshake_Body(self):
        self.handshak_version = self.protocol_version["TLS1.2"]
        self.random = self.make_random()
        self.session_id_length = b'\x00'
        self.session_id = b''
        self.ciper_suites_length = b''
        self.ciper_suites = b'\xc0\x2c\xc0\x30\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\x00\x9f\x00\x9e\xcc\xaa\xc0\xaf\xc0\xad\xc0\xae\xc0\xac\xc0\x24\xc0\x28\xc0\x23\xc0\x27\xc0\x0a\xc0\x14\xc0\x09\xc0\x13\xc0\xa3\xc0\x9f\xc0\xa2\xc0\x9e\x00\x6b\x00\x67\x00\x39\x00\x33\x00\x9d\x00\x9c\xc0\xa1\xc0\x9d\xc0\xa0\xc0\x9c\x00\x3d\x00\x3c\x00\x35\x00\x2f\x00\xff'
        self.compression_methods_length = b'\x01'
        self.compression_methods = b'\x00'

    def Handshake_Body_byte(self):
        byte_data = self.handshak_version + self.random + self.session_id_length + self.session_id + \
            self.ciper_suites_length + self.ciper_suites + \
            self.compression_methods_length + self.compression_methods
        return byte_data

    def ssl_len(self):
        self.compression_methods_length = len(
            self.compression_methods).to_bytes(1, 'big')  # length is 1

        self.session_id_length = len(
            self.session_id).to_bytes(1, 'big')  # length is 2

        self.ciper_suites_length = len(
            self.ciper_suites).to_bytes(2, 'big')  # length is 2

        self.handshak_length = len(
            self.Handshake_Body_byte()).to_bytes(3, 'big')

        self.length = len(self.Handshake_Header_byte() +
                          self.Handshake_Body_byte()).to_bytes(2, 'big')

    def make_random(self):
        sum = b""
        for i in range(32):
            x = random.randrange(256)
            sum = x.to_bytes(1, 'big') + bytes(sum)
        return sum


def main():
    port = 443
    destination_ip = "127.0.0.1"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((destination_ip, port))
        except ConnectionRefusedError as err:
            print(err)
            return
        print("tcp connected")
        tls = TLS_Analyze()
        tls.TLS_Record_Layer()
        tls.Handshake_Header()
        tls.Handshake_Body()
        tls.ssl_len()
        tls_byte = tls.TLS_Record_Layer_byte() + tls.Handshake_Header_byte() + \
            tls.Handshake_Body_byte()

        sock.send(tls_byte)

        recv_data = sock.recv(1024)
        print(recv_data)
        recv_data = sock.recv(1024)
        print(recv_data)

        sleep(3)


if __name__ == '__main__':
    main()
