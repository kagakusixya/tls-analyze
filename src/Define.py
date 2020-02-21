class Define:
    def __init__(self):
        self.Define()

    def Define(self):
        self.define_content_type = {"change_cipher_spec": b'\x14', "alert": b'\x15',
                                    "handshake": b'\x16', "application_data": b'\x17'}
        self.define_protocol_version = {
            "TLS1.0": b'\x03\x01', "TLS1.2": b'\x03\x03'}
        self.define_size = {"compression_method": 1,"ciper_suite": 2,"random": 32,"handshak_version": 2,"handshake_type": 1, "version": 2, "content_type": 1, "length": 2, "handshak_length": 3,
                            "ciper_suites_length": 2, "session_id_length": 1, "compression_methods_length": 1, "extension_length": 2}
        self.define_handshake_type = {"hello_request": b'\x00', "client_hello": b'\x01', "server_hello": b'\x02', "certificate": b'\x0b', "server_key_exchange": b'\x0c',
                                      "certificate_request": b'\x0d', "server_hello_done": b'\x0e', "certificate_verify": b'\x0f', "client_key_exchange": b'\x10', "finished": b'\x11'}
