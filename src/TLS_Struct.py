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

class  Handshake_Header:
    def __init__(self):
        self.handshake_type = Define().define_handshake_type["client_hello"]
        self.handshak_length = b'\x00\x00\x00'

    def Handshake_Header_byte(self):
        byte_data = self.handshake_type + self.handshak_length
        return byte_data

    def Handshake_Header_len(self, str):
        if hasattr(self, 'handshak_length'):
            self.handshak_length = len(str).to_bytes(Define().define_size["handshak_length"], 'big')
