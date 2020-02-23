class Define:
    def __init__(self):
        self.Define()

    def Define(self):
        self.define_content_type = {"change_cipher_spec": b'\x14', "alert": b'\x15',
                                    "handshake": b'\x16', "application_data": b'\x17'}
        self.define_protocol_version = {
            "TLS1.0": b'\x03\x01', "TLS1.2": b'\x03\x03'}
        self.define_size = {"compression_method": 1, "cipher_suite": 2, "random": 32, "handshak_version": 2, "handshake_type": 1, "version": 2, "content_type": 1, "length": 2, "handshak_length": 3,
                            "cipher_suites_length": 2, "session_id_length": 1, "compression_methods_length": 1, "extension_length": 2}
        self.define_handshake_type = {"hello_request": b'\x00', "client_hello": b'\x01', "server_hello": b'\x02', "certificate": b'\x0b', "server_key_exchange": b'\x0c',
                                      "certificate_request": b'\x0d', "server_hello_done": b'\x0e', "certificate_verify": b'\x0f', "client_key_exchange": b'\x10', "finished": b'\x11'}
        self.define_cipher_suite = {"TLS_NULL_WITH_NULL_NULL": b'\x00\x00', "CipherSuite TLS_RSA_WITH_NULL_MD5": b'\x00\x01', "TLS_RSA_WITH_NULL_SHA": b'\x00\x02', "TLS_RSA_EXPORT_WITH_RC4_40_MD5": '\x00\x03', "TLS_RSA_WITH_RC4_128_MD5": b'\x00\x04', "TLS_RSA_WITH_RC4_128_SHA": b'\x00\x05', "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5": b'\x00\x06', "TLS_RSA_WITH_IDEA_CBC_SHA": b'\x00\x07', "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA": b'\x00\x08', "TLS_RSA_WITH_DES_CBC_SHA": '\x00\x09', "TLS_RSA_WITH_3DES_EDE_CBC_SHA": '\x00\x0a', "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA": '\x00\x0b', "TLS_DH_DSS_WITH_DES_CBC_SHA": '\x00\x0c', "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA": '\x00\x0d',
                                    "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA": '\x00\x0e', "TLS_DH_RSA_WITH_DES_CBC_SHA": '\x00\x0f', "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA": '\x00\x10', "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA": '\x00\x11', "TLS_DHE_DSS_WITH_DES_CBC_SHA": '\x00\x12', "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA": '\x00\x13', "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA ": '\x00\x14', "TLS_DHE_RSA_WITH_DES_CBC_SHA": '\x00\x15', "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA": '\x00\x16', "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5": '\x00\x17', "TLS_DH_anon_WITH_RC4_128_MD5": '\x00\x18', "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA": '\x00\x19', "TLS_DH_anon_WITH_DES_CBC_SHA": '\x00\x1a', "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA": '\x00\x1b'}
