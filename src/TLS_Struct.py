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
        self.handshake_type = b''
        self.handshak_length = b'\x00\x00\x00'

    def Handshake_Header_byte(self):
        byte_data = self.handshake_type + self.handshak_length
        return byte_data

    def Handshake_Header_len(self, str):
        self.handshak_length = len(str).to_bytes(
            Define().define_size["handshak_length"], 'big')


class Client_Hello:
    def __init__(self):
        self.handshak_version = Define().define_protocol_version["TLS1.2"]
        self.random = make_random()
        self.session_id_length = b'\x00'
        self.session_id = b''
        self.cipher_suites_length = b''
        self.cipher_suites = Define(
        ).define_cipher_suite["TLS_NULL_WITH_NULL_NULL"]
        self.compression_methods_length = b'\x01'
        self.compression_methods = b'\x00'
        self.extension_length = b'\x00\x00'
        self.extensions = b''

        self.Extension()

    def byte(self):
        byte_data = self.handshak_version + self.random + self.session_id_length + self.session_id + \
            self.cipher_suites_length + self.cipher_suites + \
            self.compression_methods_length + self.compression_methods + \
            self.extension_length + self.extensions
        return byte_data

    def len(self):
        self.extension_length = len(self.Extension_byte()).to_bytes(
            Define().define_size["extension_length"], 'big')  # length is 2

        self.compression_methods_length = len(self.compression_methods).to_bytes(
            Define().define_size["compression_methods_length"], 'big')  # length is 1

        self.session_id_length = len(self.session_id).to_bytes(
            Define().define_size["session_id_length"], 'big')  # length is 2

        self.cipher_suites_length = len(self.cipher_suites).to_bytes(
            Define().define_size["cipher_suites_length"], 'big')  # length is 2

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


class Server_Hello:
    def __init__(self):
        self.handshak_version = Define().define_protocol_version["TLS1.2"]
        self.random = make_random()
        self.session_id_length = b'\x00'
        self.session_id = b''
        self.cipher_suite = b''
        self.compression_method = b'\x00'
        self.extension_length = b'\x00\x00'
        self.extensions = b''

    def Server_Hello_byte(self):
        byte_data = self.handshak_version + self.random + self.session_id_length + \
            self.cipher_suite + self.compression_method + \
            self.extension_length + self.extensions
        return byte_data


class Certificate:
    def __init__(self):
        self.certificate_struct_length = b''
        self.certificate_length = b''
        self.certificate = []

class Server_Key_Exchange:
    def __init__(self):
        self.curve_type = b''
        self.named_curve = b''
        self.pubkey_length = b''
        self.pubkey = b''
        self.algorithms_hash = b''
        self.algorithms_signature = b''
        self.signature_length = b''
        self.signature = b''

class Client_Key_Exchange:
    def __init__(self):
        self.pubkey_length = b''
        self.pubkey = b''

    def byte(self):
        byte_data = self.pubkey_length + self.pubkey
        return  byte_data

    def len(self):
        self.pubkey_length = len(self.pubkey).to_bytes(
            Define().define_size["pubkey_length"], 'big')

class Finished:
    def __init__(self):
        self.finished_verify_data = b''

    def byte(self):
        return self.finished_verify_data

    def len(self):
        pass

class TLS_Handshake_Basic:
    def __init__(self):
        self.tls_record_layer  = TLS_Record_Layer()
        self.tls_record_layer.content_type = Define().define_content_type["handshake"]
        self.handshake_header  = Handshake_Header()
        self.payload         =  None

    def setlen(self):
        self.payload.len()
        self.tls_record_layer.TLS_Record_Layer_len(
            self.handshake_header.Handshake_Header_byte() + self.payload.byte())
        self.handshake_header.Handshake_Header_len(self.payload.byte())

class TLS_Change_Cipher_Spec_Basic:
    def __init__(self):
        self.tls_record_layer  = TLS_Record_Layer()
        self.tls_record_layer.content_type = Define().define_content_type["change_cipher_spec"]
        self.change_cipher_spec_message = b'\x01'

    def setlen(self):
        self.tls_record_layer.TLS_Record_Layer_len(self.change_cipher_spec_message)


def make_random():
    sum = b""
    for i in range(Define().define_size["random"]):
        x = random.randrange(256)
        sum = x.to_bytes(1, 'big') + bytes(sum)
    return sum
