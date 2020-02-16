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
