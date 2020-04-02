class Define:
    def __init__(self):
        self.Define()

    def Define(self):
        self.define_content_type = {"change_cipher_spec": b'\x14', "alert": b'\x15',
                                    "handshake": b'\x16', "application_data": b'\x17'}

        self.define_protocol_version = {
            "TLS1.0": b'\x03\x01', "TLS1.2": b'\x03\x03'}

        self.define_size = {"finished_verify_data":12,"signature_length": 2, "algorithms_signature": 1, "algorithms_hash": 1, "pubkey_length": 1, "named_curve": 2, "curve_type": 1, "certificate_struct_length": 3, "certificate_length": 3, "compression_method": 1, "cipher_suite": 2, "random": 32, "handshak_version": 2, "handshake_type": 1, "version": 2, "content_type": 1, "length": 2, "handshak_length": 3,
                            "cipher_suites_length": 2, "session_id_length": 1, "compression_methods_length": 1, "extension_length": 2}

        self.define_handshake_type = {"hello_request": b'\x00', "client_hello": b'\x01', "server_hello": b'\x02', "certificate": b'\x0b', "server_key_exchange": b'\x0c',
                                      "certificate_request": b'\x0d', "server_hello_done": b'\x0e', "certificate_verify": b'\x0f', "client_key_exchange": b'\x10', "finished": b'\x11'}

        self.define_curve_type = {"explicit_prime": b'\x01', "explicit_char2": b'\x02', "named_curve": b'\x03',
                                  "reserved(248)": b'\xf8', "reserved(249)": b'\xf9', "reserved(250)": b'\xfa', "reserved(251)": b'\xfb', "reserved(252)": b'\xfc', "reserved(253)": b'\xfd', "reserved(254)": b'\xfe', "reserved(255)": b'\xff'}

        self.define_named_curve = {
            "sect163k1": b'\x00\x01', "sect163r1": b'\x00\x02', "sect163r2": b'\x00\x03', "sect193r1": b'\x00\x04', "sect193r2": b'\x00\x05', "sect233k1": b'\x00\x06', "sect233r1": b'\x00\x07', "sect239k1": b'\x00\x08', "sect283k1": b'\x00\x09', "sect283r1": b'\x00\x0a', "sect409k1": b'\x00\x0b', "sect409r1": b'\x00\x0c', "sect571k1": b'\x00\x0d', "sect571k1": b'\x00\x0c', "sect571r1": b'\x00\x0d', "secp160k1": b'\x00\x0e', "secp160r1": b'\x00\x0f', "secp160r2": b'\x00\x11', "secp192k1": b'\x00\x12', "secp192r1": b'\x00\x13', "secp224k1": b'\x00\x14', "secp224r1": b'\x00\x15', "secp256k1": b'\x00\x16', "secp256r1": b'\x00\x17', "secp384r1": b'\x00\x18', "secp521r1": b'\x00\x19', "arbitrary_explicit_prime_curves": b'\xff\x01', "arbitrary_explicit_char2_curves": b'\xff\x02'}

        self.define_algorithms_hash = {
            "none": b'\x00', "MD5": b'\x01', "SHA": b'\x02', "SHA224:": b'\x03', "SHA256": b'\x04', "SGA384": b'\x05', "SGA512": b'\x06'}

        self.define_algorithms_signature = {
            "ANONYMOUS": b'\x00', "RSA": b'\x01', "DSA": b'\x02', "ECDSA": b'\x03'}

        self.define_cipher_suite = {"TLS_NULL_WITH_NULL_NULL": b'\x00\x00', "TLS_RSA_WITH_NULL_MD5": b'\x00\x01', "TLS_RSA_WITH_NULL_SHA": b'\x00\x02', "TLS_RSA_EXPORT_WITH_RC4_40_MD5": b'\x00\x03', "TLS_RSA_WITH_RC4_128_MD5": b'\x00\x04', "TLS_RSA_WITH_RC4_128_SHA": b'\x00\x05', "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5": b'\x00\x06', "TLS_RSA_WITH_IDEA_CBC_SHA": b'\x00\x07', "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA": b'\x00\x08', "TLS_RSA_WITH_DES_CBC_SHA": b'\x00\x09', "TLS_RSA_WITH_3DES_EDE_CBC_SHA": b'\x00\x0a', "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA": b'\x00\x0b', "TLS_DH_DSS_WITH_DES_CBC_SHA": b'\x00\x0c', "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA": b'\x00\x0d', "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA": b'\x00\x0e', "TLS_DH_RSA_WITH_DES_CBC_SHA": b'\x00\x0f', "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA": b'\x00\x10', "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA": b'\x00\x11', "TLS_DHE_DSS_WITH_DES_CBC_SHA": b'\x00\x12', "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA": b'\x00\x13', "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA": b'\x00\x14', "TLS_DHE_RSA_WITH_DES_CBC_SHA": b'\x00\x15', "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA": b'\x00\x16', "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5": b'\x00\x17', "TLS_DH_anon_WITH_RC4_128_MD5": b'\x00\x18', "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA": b'\x00\x19', "TLS_DH_anon_WITH_DES_CBC_SHA": b'\x00\x1a', "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA": b'\x00\x1b', "SSL_FORTEZZA_KEA_WITH_NULL_SHA": b'\x00\x1c', "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA": b'\x00\x1d', "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA": b'\x00\x1e', "TLS_KRB5_WITH_DES_CBC_SHA": b'\x00\x1e', "TLS_KRB5_WITH_3DES_EDE_CBC_SHA": b'\x00\x1f', "TLS_KRB5_WITH_RC4_128_SHA": b'\x00\x20', "TLS_KRB5_WITH_IDEA_CBC_SHA": b'\x00\x21', "TLS_KRB5_WITH_DES_CBC_MD5": b'\x00\x22', "TLS_KRB5_WITH_3DES_EDE_CBC_MD5": b'\x00\x23', "TLS_KRB5_WITH_RC4_128_MD5": b'\x00\x24', "TLS_KRB5_WITH_IDEA_CBC_MD5": b'\x00\x25', "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA": b'\x00\x26', "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA": b'\x00\x27', "TLS_KRB5_EXPORT_WITH_RC4_40_SHA": b'\x00\x28', "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5": b'\x00\x29', "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5": b'\x00\x2a', "TLS_KRB5_EXPORT_WITH_RC4_40_MD5": b'\x00\x2b', "TLS_PSK_WITH_NULL_SHA": b'\x00\x2c', "TLS_DHE_PSK_WITH_NULL_SHA": b'\x00\x2d', "TLS_RSA_PSK_WITH_NULL_SHA": b'\x00\x2e', "TLS_RSA_WITH_AES_128_CBC_SHA": b'\x00\x2f', "TLS_DH_DSS_WITH_AES_128_CBC_SHA": b'\x00\x30', "TLS_DH_RSA_WITH_AES_128_CBC_SHA": b'\x00\x31', "TLS_DHE_DSS_WITH_AES_128_CBC_SHA": b'\x00\x32', "TLS_DHE_RSA_WITH_AES_128_CBC_SHA": b'\x00\x33', "TLS_DH_anon_WITH_AES_128_CBC_SHA": b'\x00\x34', "TLS_RSA_WITH_AES_256_CBC_SHA": b'\x00\x35', "TLS_DH_DSS_WITH_AES_256_CBC_SHA": b'\x00\x36', "TLS_DH_RSA_WITH_AES_256_CBC_SHA": b'\x00\x37', "TLS_DHE_DSS_WITH_AES_256_CBC_SHA": b'\x00\x38', "TLS_DHE_RSA_WITH_AES_256_CBC_SHA": b'\x00\x39', "TLS_DH_anon_WITH_AES_256_CBC_SHA": b'\x00\x3a', "TLS_RSA_WITH_NULL_SHA256": b'\x00\x3b', "TLS_RSA_WITH_AES_128_CBC_SHA256": b'\x00\x3c', "TLS_RSA_WITH_AES_256_CBC_SHA256": b'\x00\x3d', "TLS_DH_DSS_WITH_AES_128_CBC_SHA256": b'\x00\x3e', "TLS_DH_RSA_WITH_AES_128_CBC_SHA256": b'\x00\x3f', "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256": b'\x00\x40', "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA": b'\x00\x41', "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA": b'\x00\x42', "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA": b'\x00\x43', "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA": b'\x00\x44', "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA": b'\x00\x45', "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA": b'\x00\x46', "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA": b'\x00\x62', "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA": b'\x00\x63', "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA": b'\x00\x64', "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA": b'\x00\x65', "TLS_DHE_DSS_WITH_RC4_128_SHA": b'\x00\x66', "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256": b'\x00\x67', "TLS_DH_DSS_WITH_AES_256_CBC_SHA256": b'\x00\x68', "TLS_DH_RSA_WITH_AES_256_CBC_SHA256": b'\x00\x69', "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256": b'\x00\x6a', "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256": b'\x00\x6b', "TLS_DH_anon_WITH_AES_128_CBC_SHA256": b'\x00\x6c', "TLS_DH_anon_WITH_AES_256_CBC_SHA256": b'\x00\x6d', "TLS_GOSTR341094_WITH_28147_CNT_IMIT": b'\x00\x80', "TLS_GOSTR341001_WITH_28147_CNT_IMIT": b'\x00\x81', "TLS_GOSTR341094_WITH_NULL_GOSTR3411": b'\x00\x82', "TLS_GOSTR341001_WITH_NULL_GOSTR3411": b'\x00\x83', "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA": b'\x00\x84', "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA": b'\x00\x85', "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA": b'\x00\x86', "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA": b'\x00\x87', "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA": b'\x00\x88', "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA": b'\x00\x89', "TLS_PSK_WITH_RC4_128_SHA": b'\x00\x8a', "TLS_PSK_WITH_3DES_EDE_CBC_SHA": b'\x00\x8b', "TLS_PSK_WITH_AES_128_CBC_SHA": b'\x00\x8c', "TLS_PSK_WITH_AES_256_CBC_SHA": b'\x00\x8d', "TLS_DHE_PSK_WITH_RC4_128_SHA": b'\x00\x8e', "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA": b'\x00\x8f',
                                    "TLS_DHE_PSK_WITH_AES_128_CBC_SHA": b'\x00\x90', "TLS_DHE_PSK_WITH_AES_256_CBC_SHA": b'\x00\x91', "TLS_RSA_PSK_WITH_RC4_128_SHA": b'\x00\x92', "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA": b'\x00\x93', "TLS_RSA_PSK_WITH_AES_128_CBC_SHA": b'\x00\x94', "TLS_RSA_PSK_WITH_AES_256_CBC_SHA": b'\x00\x95', "TLS_RSA_WITH_SEED_CBC_SHA": b'\x00\x96', "TLS_DH_DSS_WITH_SEED_CBC_SHA": b'\x00\x97', "TLS_DH_RSA_WITH_SEED_CBC_SHA": b'\x00\x98', "TLS_DHE_DSS_WITH_SEED_CBC_SHA": b'\x00\x99', "TLS_DHE_RSA_WITH_SEED_CBC_SHA": b'\x00\x9a', "TLS_DH_anon_WITH_SEED_CBC_SHA": b'\x00\x9b', "TLS_RSA_WITH_AES_128_GCM_SHA256": b'\x00\x9c', "TLS_RSA_WITH_AES_256_GCM_SHA384": b'\x00\x9d', "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": b'\x00\x9e', "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": b'\x00\x9f', "TLS_DH_RSA_WITH_AES_128_GCM_SHA256": b'\x00\xa0', "TLS_DH_RSA_WITH_AES_256_GCM_SHA384": b'\x00\xa1', "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256": b'\x00\xa2', "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384": b'\x00\xa3', "TLS_DH_DSS_WITH_AES_128_GCM_SHA256": b'\x00\xa4', "TLS_DH_DSS_WITH_AES_256_GCM_SHA384": b'\x00\xa5', "TLS_DH_Anon_WITH_AES_128_GCM_SHA256": b'\x00\xa6', "TLS_DH_Anon_WITH_AES_256_GCM_SHA384": b'\x00\xa7', "TLS_PSK_WITH_AES_128_GCM_SHA256": b'\x00\xa8', "TLS_PSK_WITH_AES_256_GCM_SHA384": b'\x00\xa9', "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256": b'\x00\xaa', "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384": b'\x00\xab', "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256": b'\x00\xac', "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384": b'\x00\xad', "TLS_PSK_WITH_AES_128_CBC_SHA256": b'\x00\xae', "TLS_PSK_WITH_AES_256_CBC_SHA384": b'\x00\xaf', "TLS_PSK_WITH_NULL_SHA256": b'\x00\xb0', "TLS_PSK_WITH_NULL_SHA384": b'\x00\xb1', "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256": b'\x00\xb2', "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384": b'\x00\xb3', "TLS_DHE_PSK_WITH_NULL_SHA256": b'\x00\xb4', "TLS_DHE_PSK_WITH_NULL_SHA384": b'\x00\xb5', "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256": b'\x00\xb6', "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384": b'\x00\xb7', "TLS_RSA_PSK_WITH_NULL_SHA256": b'\x00\xb8', "TLS_RSA_PSK_WITH_NULL_SHA384": b'\x00\xb9', "TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746)": b'\x00\xff', "TLS_ECDH_ECDSA_WITH_NULL_SHA": b'\xc0\x01', "TLS_ECDH_ECDSA_WITH_RC4_128_SHA": b'\xc0\x02', "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA": b'\xc0\x03', "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA": b'\xc0\x04', "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA": b'\xc0\x05', "TLS_ECDHE_ECDSA_WITH_NULL_SHA": b'\xc0\x06', "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA": b'\xc0\x07', "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA": b'\xc0\x08', "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": b'\xc0\x09', "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": b'\xc0\x0a', "TLS_ECDH_RSA_WITH_NULL_SHA": b'\xc0\x0b', "TLS_ECDH_RSA_WITH_RC4_128_SHA": b'\xc0\x0c', "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA": b'\xc0\x0d', "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA": b'\xc0\x0e', "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA": b'\xc0\x0f', "TLS_ECDHE_RSA_WITH_NULL_SHA": b'\xc0\x10', "TLS_ECDHE_RSA_WITH_RC4_128_SHA": b'\xc0\x11', "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": b'\xc0\x12', "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": b'\xc0\x13', "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": b'\xc0\x14', "TLS_ECDH_anon_WITH_NULL_SHA": b'\xc0\x15', "TLS_ECDH_anon_WITH_RC4_128_SHA": b'\xc0\x16', "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA": b'\xc0\x17', "TLS_ECDH_anon_WITH_AES_128_CBC_SHA": b'\xc0\x18', "TLS_ECDH_anon_WITH_AES_256_CBC_SHA": b'\xc0\x19', "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA": b'\xc0\x1a', "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA": b'\xc0\x1b', "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA": b'\xc0\x1c', "TLS_SRP_SHA_WITH_AES_128_CBC_SHA": b'\xc0\x1d', "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA": b'\xc0\x1e', "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA": b'\xc0\x1f', "TLS_SRP_SHA_WITH_AES_256_CBC_SHA": b'\xc0\x20', "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA": b'\xc0\x21', "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA": b'\xc0\x22', "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": b'\xc0\x23', "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": b'\xc0\x24', "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256": b'\xc0\x25', "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384": b'\xc0\x26', "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": b'\xc0\x27', "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": b'\xc0\x28', "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256": b'\xc0\x29', "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384": b'\xc0\x2a', "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": b'\xc0\x2b', "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": b'\xc0\x2c', "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256": b'\xc0\x2d', "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384": b'\xc0\x2e', "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": b'\xc0\x2f', "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": b'\xc0\x30', "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256": b'\xc0\x31', "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384": b'\xc0\x32', "SSL_RSA_FIPS_WITH_DES_CBC_SHA": b'\xfe\xfe', "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA": b'\xfe\xff', "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA": b'\xff\xe0', "SSL_RSA_FIPS_WITH_DES_CBC_SHA": b'\xff\xe1'}
