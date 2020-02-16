import random

from Define import *


class TLS_Record_Layer:
    def __init__(self):
        self.content_type = Define().define_content_type["handshake"]
        self.version = Define().define_protocol_version["TLS1.0"]
        self.length = b'\x00\x00'

    def TLS_Record_Layer_byte(self):
        byte_data = self.content_type + self.version + self.length
        return byte_data

    def TLS_Record_Layer_len(self, str):
        self.length = len(str).to_bytes(Define().define_size["length"], 'big')


class Handshake_Header:
    def __init__(self):
        self.handshake_type = Define().define_handshake_type["client_hello"]
        self.handshak_length = b'\x00\x00\x00'

    def Handshake_Header_byte(self):
        byte_data = self.handshake_type + self.handshak_length
        return byte_data

    def Handshake_Header_len(self, str):
        if hasattr(self, 'handshak_length'):
            self.handshak_length = len(str).to_bytes(
                Define().define_size["handshak_length"], 'big')


class Client_Hello:
    def __init__(self):
        self.handshak_version = Define().define_protocol_version["TLS1.2"]
        self.random = make_random()
        self.session_id_length = b'\x00'
        self.session_id = b''
        self.ciper_suites_length = b''
        self.ciper_suites = b'\xc0\x2c\xc0\x30\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\x00\x9f\x00\x9e\xcc\xaa\xc0\xaf\xc0\xad\xc0\xae\xc0\xac\xc0\x24\xc0\x28\xc0\x23\xc0\x27\xc0\x0a\xc0\x14\xc0\x09\xc0\x13\xc0\xa3\xc0\x9f\xc0\xa2\xc0\x9e\x00\x6b\x00\x67\x00\x39\x00\x33\x00\x9d\x00\x9c\xc0\xa1\xc0\x9d\xc0\xa0\xc0\x9c\x00\x3d\x00\x3c\x00\x35\x00\x2f\x00\xff'
        self.compression_methods_length = b'\x01'
        self.compression_methods = b'\x00'
        self.extension_length = b'\x00\x00'
        self.extensions = b''

        self.Extension()

    def Client_Hello_byte(self):
        byte_data = self.handshak_version + self.random + self.session_id_length + self.session_id + \
            self.ciper_suites_length + self.ciper_suites + \
            self.compression_methods_length + self.compression_methods + \
            self.extension_length + self.extensions
        return byte_data

    def Client_Hello_len(self):
        if hasattr(self, 'extension_length'):
            self.extension_length = len(
                self.Extension_byte()).to_bytes(Define().define_size["extension_length"], 'big')  # length is 2

        if hasattr(self, 'compression_methods_length'):
            self.compression_methods_length = len(
                self.compression_methods).to_bytes(Define().define_size["compression_methods_length"], 'big')  # length is 1

        if hasattr(self, 'session_id_length'):
            self.session_id_length = len(
                self.session_id).to_bytes(Define().define_size["session_id_length"], 'big')  # length is 2

        if hasattr(self, 'ciper_suites_length'):
            self.ciper_suites_length = len(
                self.ciper_suites).to_bytes(Define().define_size["ciper_suites_length"], 'big')  # length is 2

    def Extension(self):
        self.ec_point_formats = b'\x00\x0b\x00\x04\x03\x00\x01\x02'
        self.supported_groups = b'\x00\x0a\x00\x04\x00\x02\x00\x17'
        self.sessionticket_tls = b'\x00\x23\x00\x00'
        self.encrypt_then_mac = b'\x00\x16\x00\x00'
        self.extended_master_secret = b'\x00\x17\x00\x00'
        self.signature_algorithms = b'\x00\x0d\x00\x20\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03'

    def Extension_byte(self):
        byte_data = self.ec_point_formats + self.supported_groups + self.sessionticket_tls + \
            self.encrypt_then_mac + self.extended_master_secret + self.signature_algorithms
        return byte_data
def make_random():
    sum = b""
    for i in range(32):
        x = random.randrange(256)
        sum = x.to_bytes(1, 'big') + bytes(sum)
    return sum