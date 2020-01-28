class TLS_Analyze:
    def __init__(self):
        Define()
        TLS_Record_Layer()

    def Define(self):
        self.content_type = {"change_cipher_spec": b'\x14', "alert": b'\x15',
                             "handshake": b'\x16', "application_data": b'\x17'}
        self.protocol_version = {"TLS1.0": b'\x03\x01', "TLS1.2": b'\x03\x03'}
