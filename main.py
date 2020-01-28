import socket
from time import sleep
import random


class TLS_Record_Layer:
    def __init__(self):
        self.content_type = b'\x16'
        self.version      = b'\x03\x01'
        self.length       = b'\x00\x00'
        #Handshal
        self.handshake_type             = b'\x01'
        self.handshak_length            = b'\x00\x00\x00'
        self.handshak_version           = b'\x03\x03'
        self.random                     = b''
        self.session_id_length          = b'\x00'
        self.session_id                 = b''
        self.ciper_suites_length        = b''
        self.ciper_suites               = b'\xc0\x2c\xc0\x30\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\x00\x9f\x00\x9e\xcc\xaa\xc0\xaf\xc0\xad\xc0\xae\xc0\xac\xc0\x24\xc0\x28\xc0\x23\xc0\x27\xc0\x0a\xc0\x14\xc0\x09\xc0\x13\xc0\xa3\xc0\x9f\xc0\xa2\xc0\x9e\x00\x6b\x00\x67\x00\x39\x00\x33\x00\x9d\x00\x9c\xc0\xa1\xc0\x9d\xc0\xa0\xc0\x9c\x00\x3d\x00\x3c\x00\x35\x00\x2f\x00\xff'
        self.compression_methods_length = b'\x01'
        self.compression_methods        = b'\x00'
        self.extension_length           = b'\x00\x00'
        self.ec_point_formats           = b'\x00\x0b\x00\x04\x03\x00\x01\x02'
        self.supported_groups           = b'\x00\x0a\x00\x04\x00\x02\x00\x17'
        self.sessionticket_tls          = b'\x00\x23\x00\x00'
        self.encrypt_then_mac           = b'\x00\x16\x00\x00'
        self.extended_master_secret     = b'\x00\x17\x00\x00'
        self.signature_algorithms       = b'\x00\x0d\x00\x20\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03'


        #Extension
    def ssl_bytes(self):
        data = self.content_type+\
               self.version+\
               self.length+\
               self.handshake_type +\
               self.handshak_length +\
               self.handshak_version +\
               self.random +\
               self.session_id_length +\
               self.session_id +\
               self.ciper_suites_length +\
               self.ciper_suites +\
               self.compression_methods_length +\
               self.compression_methods +\
               self.extension_length +\
               self.ec_point_formats +\
               self.supported_groups +\
               self.sessionticket_tls +\
               self.encrypt_then_mac +\
               self.extended_master_secret +\
               self.signature_algorithms
        return data

    def ssl_len(self):


        self.ciper_suites_length  = len(self.ciper_suites).to_bytes(2,'big') #length is 2
        self.compression_methods_length  = len(self.compression_methods).to_bytes(1,'big') #length is 1
        self.session_id_length    = len(self.session_id).to_bytes(1,'big') #length is 2

        extension_data =    self.ec_point_formats +\
                       self.supported_groups +\
                       self.sessionticket_tls +\
                       self.encrypt_then_mac +\
                       self.extended_master_secret +\
                       self.signature_algorithms
        self.extension_length    = len(extension_data).to_bytes(2,'big') #length is 2

        handshak_length_data = self.handshak_version +\
                               self.random +\
                               self.session_id_length +\
                               self.session_id +\
                               self.ciper_suites_length +\
                               self.ciper_suites +\
                               self.compression_methods_length +\
                               self.compression_methods +\
                               self.extension_length +\
                               self.ec_point_formats +\
                               self.supported_groups +\
                               self.sessionticket_tls +\
                               self.encrypt_then_mac +\
                               self.extended_master_secret +\
                               self.signature_algorithms

        self.handshak_length = len(handshak_length_data).to_bytes(3,'big')

        self.length = len(self.handshake_type + self.handshak_length + handshak_length_data ).to_bytes(2,'big')



    def make_random(self):
        sum = b""
        for i in range(32):
            x = random.randrange(256)
            sum = x.to_bytes(1,'big') + bytes(sum)
        self.random = sum






def main():
    port = 443
    destination_ip = "8.8.8.8"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((destination_ip,port))
        except ConnectionRefusedError as err:
            print(err)
            return
        print("tcp connected")

        tls_record_layer = TLS_Record_Layer()
        tls_record_layer.make_random()
        tls_record_layer.ssl_len()
        tls_record_layer_bytes = tls_record_layer.ssl_bytes()

        sock.send(tls_record_layer_bytes)

        recv_data = sock.recv(1024)
        print(recv_data)
        recv_data = sock.recv(1024)
        print(recv_data)

        sleep(3)



if __name__ == '__main__':
    main()
