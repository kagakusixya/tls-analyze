from Define import *


class TLS_Debug:

    def TLS_Record_Layer_Show(self, tls_record_layer):
        print("-------------------------------------------------")
        content_type_str = analyze_dict(
            tls_record_layer.content_type, Define().define_content_type)
        print("content_type :  %s" % content_type_str)

        version_str = analyze_dict(
            tls_record_layer.version, Define().define_protocol_version)
        print("version : %s" % version_str)

        print("length : %d" % int.from_bytes(tls_record_layer.length, 'big'))

    def Handshake_Header(self, handshake_header):
        handshake_type_str = analyze_dict(
            handshake_header.handshake_type, Define().define_handshake_type)
        print("handshake_type : %s" % handshake_type_str)

        print("handshak_length : %d" % int.from_bytes(
            handshake_header.handshak_length, 'big'))

    def Server_Hello(self, server_hello):
        handshak_version_str = analyze_dict(
            server_hello.handshak_version, Define().define_protocol_version)
        print("handshak_version :  %s" % handshak_version_str)

        print("random :  %s" % server_hello.random)

        print("session_id_length : %d" % int.from_bytes(
            server_hello.session_id_length, 'big'))

        print("session_id : %s" % server_hello.session_id_length)

        print("cipher_suite : %s" % analyze_dict(server_hello.cipher_suite, Define().define_cipher_suite))

        print("compression_method : %s" % server_hello.compression_method)

        print("extension_length : %d" % int.from_bytes(
            server_hello.extension_length, 'big'))

        print("extensions : %s" % server_hello.extensions)

    def Certficate(self, certificate):

        print("--Certificate--")

        print("certificate_struct_length: %d" % int.from_bytes(
            certificate.certificate_struct_length, 'big'))

        print("certificate_length: %d" % int.from_bytes(
            certificate.certificate_length, 'big'))

        for crt in certificate.certificate:
            print("certificate : %s" % crt)

    def Show(self, tls_basic):
        self.TLS_Record_Layer_Show(tls_basic.tls_record_layer)
        self.Handshake_Header(tls_basic.handshake_header)

        if Define().define_handshake_type["hello_request"] == tls_basic.handshake_header.handshake_type:
            print("hello_request")

        elif Define().define_handshake_type["client_hello"] == tls_basic.handshake_header.handshake_type:
            print("client_hello")

        elif Define().define_handshake_type["server_hello"] == tls_basic.handshake_header.handshake_type:
            self.Server_Hello(tls_basic.payload)

        elif Define().define_handshake_type["certificate"] == tls_basic.handshake_header.handshake_type:
            self.Certficate(tls_basic.payload)

        elif Define().define_handshake_type["server_key_exchange"] == tls_basic.handshake_header.handshake_type:
            print("server_key_exchange")


        elif Define().define_handshake_type["certificate_request"] == tls_basic.handshake_header.handshake_type:
            print("certificate_request")

        elif Define().define_handshake_type["server_hello_done"] == tls_basic.handshake_header.handshake_type:
            print("server_hello_done")

        elif Define().define_handshake_type["certificate_verify"] == tls_basic.handshake_header.handshake_type:
            print("certificate_verify")

        elif Define().define_handshake_type["client_key_exchange"] == tls_basic.handshake_header.handshake_type:
            print("client_key_exchange")

        elif Define().define_handshake_type["finished"] == tls_basic.handshake_header.handshake_type:
            print("finished")

        else:
            print("handshake_type err : %s" % tls_basic.handshake_header.handshake_type)




def analyze_dict(data, dict):
    result = None
    for key, val in dict.items():
        if data == val:
            result = key
    return result
