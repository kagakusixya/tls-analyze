import socket
from time import sleep

from Define import *
from TLS_Struct import *


class TLS_Analyze:
    def __init__(self):
        self.done = 0
        self.point_length = 0
        self.tls_basics = {}
        # 0 is no done
        # 1 is done
        # -1 is alert

    def Separate_Str(self, str, point_length, len):
        separate_data = b''
        for i in range(len):
            separate_data = separate_data + str[i +
                                                point_length].to_bytes(1, 'big')
        point_length = len + point_length
        return point_length, separate_data

    def Analyze_Packet(self, str, point_length):

        tls_basic = TLS_Basic()

        point_length, tls_basic.tls_record_layer.content_type = self.Separate_Str(
            str, point_length, Define().define_size["content_type"])

        point_length, tls_basic.tls_record_layer.version = self.Separate_Str(
            str, point_length, Define().define_size["version"])

        point_length, tls_basic.tls_record_layer.length = self.Separate_Str(
            str, point_length, Define().define_size["length"])

        if tls_basic.tls_record_layer.content_type == Define().define_content_type["alert"]:
            print("alert err")
            self.done = -1
            return point_length
        # Handshake_Header
        point_length, tls_basic.handshake_header.handshake_type = self.Separate_Str(
            str, point_length, Define().define_size["handshake_type"])

        point_length, tls_basic.handshake_header.handshak_length = self.Separate_Str(
            str, point_length, Define().define_size["handshak_length"])

        if Define().define_handshake_type["hello_request"] == tls_basic.handshake_header.handshake_type:
            pass

        elif Define().define_handshake_type["client_hello"] == tls_basic.handshake_header.handshake_type:
            pass

        elif Define().define_handshake_type["server_hello"] == tls_basic.handshake_header.handshake_type:
            tls_basic.payload = self.Server_Hello_Analyze(str[point_length:  point_length + int.from_bytes(
                tls_basic.handshake_header.handshak_length, 'big')])
            point_length = point_length + int.from_bytes(
                tls_basic.handshake_header.handshak_length, 'big')

        elif Define().define_handshake_type["certificate"] == tls_basic.handshake_header.handshake_type:
            tls_basic.payload = self.Certficate(str[point_length:  point_length + int.from_bytes(
                tls_basic.handshake_header.handshak_length, 'big')])
            point_length = point_length + int.from_bytes(
                tls_basic.handshake_header.handshak_length, 'big')

        elif Define().define_handshake_type["server_key_exchange"] == tls_basic.handshake_header.handshake_type:
            point_length = point_length + int.from_bytes(
                tls_basic.handshake_header.handshak_length, 'big')

        elif Define().define_handshake_type["certificate_request"] == tls_basic.handshake_header.handshake_type:
            point_length = point_length + int.from_bytes(
                tls_basic.handshake_header.handshak_length, 'big')

        elif Define().define_handshake_type["server_hello_done"] == tls_basic.handshake_header.handshake_type:
            self.done = 1
            point_length = point_length + int.from_bytes(
                tls_basic.handshake_header.handshak_length, 'big')

        elif Define().define_handshake_type["certificate_verify"] == tls_basic.handshake_header.handshake_type:
            point_length = point_length + int.from_bytes(
                tls_basic.handshake_header.handshak_length, 'big')

        elif Define().define_handshake_type["client_key_exchange"] == tls_basic.handshake_header.handshake_type:
            point_length = point_length + int.from_bytes(
                tls_basic.handshake_header.handshak_length, 'big')

        elif Define().define_handshake_type["finished"] == tls_basic.handshake_header.handshake_type:
            point_length = point_length + int.from_bytes(
                tls_basic.handshake_header.handshak_length, 'big')

        else:
            print("handshake_type err : %s" %
                  tls_basic.handshake_header.handshake_type)

        return point_length, tls_basic

    def Server_Hello_Analyze(self, str):

        server_hello = Server_Hello()
        point_length = 0

        point_length, server_hello.handshak_version = self.Separate_Str(
            str, point_length, Define().define_size["handshak_version"])

        point_length, server_hello.random = self.Separate_Str(
            str, point_length, Define().define_size["random"])

        point_length, server_hello.session_id_length = self.Separate_Str(
            str, point_length, Define().define_size["session_id_length"])

        point_length, server_hello.session_id = self.Separate_Str(
            str, point_length,  int.from_bytes(server_hello.session_id_length, 'big'))

        point_length, server_hello.cipher_suite = self.Separate_Str(
            str, point_length, Define().define_size["cipher_suite"])

        point_length, server_hello.compression_method = self.Separate_Str(
            str, point_length, Define().define_size["compression_method"])

        point_length, server_hello.extension_length = self.Separate_Str(
            str, point_length,  Define().define_size["extension_length"])

        point_length, server_hello.extensions = self.Separate_Str(
            str, point_length, int.from_bytes(
                server_hello.extension_length, 'big'))
        return server_hello

    def Certficate(self, str):
        certificate = Certificate()
        point_length = 0

        point_length, certificate.certificate_struct_length = self.Separate_Str(
            str, point_length, Define().define_size["certificate_struct_length"])

        while point_length < len(str):
            point_length, certificate.certificate_length = self.Separate_Str(
                str, point_length, Define().define_size["certificate_length"])

            point_length, crt = self.Separate_Str(
                str, point_length, int.from_bytes(certificate.certificate_length, 'big'))

            certificate.certificate.append(crt)


        return certificate
