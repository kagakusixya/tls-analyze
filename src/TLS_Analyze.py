import socket
from time import sleep

from Define import *
from TLS_Struct import *
import base64

class TLS_Analyze:
    def __init__(self):
        self.done = 0
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

        tls_record_layer = TLS_Record_Layer()
        handshake_header = Handshake_Header()

        point_length, tls_record_layer.content_type = self.Separate_Str(
            str, point_length, Define().define_size["content_type"])
        content_type_str = analyze_dict(
            tls_record_layer.content_type, Define().define_content_type)
        print("content_type :  %s" % content_type_str)

        point_length, tls_record_layer.version = self.Separate_Str(
            str, point_length, Define().define_size["version"])
        version_str = analyze_dict(
            tls_record_layer.version, Define().define_protocol_version)
        print("version : %s" % version_str)

        point_length, tls_record_layer.length = self.Separate_Str(
            str, point_length, Define().define_size["length"])
        print("length : %d" % int.from_bytes(tls_record_layer.length, 'big'))

        if tls_record_layer.content_type == Define().define_content_type["alert"]:
            print("alert err")
            self.done = -1
            return point_length
        # Handshake_Header
        point_length, handshake_header.handshake_type = self.Separate_Str(
            str, point_length, Define().define_size["handshake_type"])
        handshake_type_str = analyze_dict(
            handshake_header.handshake_type, Define().define_handshake_type)
        print("handshake_type : %s" % handshake_type_str)

        point_length, handshake_header.handshak_length = self.Separate_Str(
            str, point_length, Define().define_size["handshak_length"])
        print("handshak_length : %d" % int.from_bytes(
            handshake_header.handshak_length, 'big'))


        if Define().define_handshake_type["hello_request"] == handshake_header.handshake_type:
            print("hello_request")

        elif Define().define_handshake_type["client_hello"] == handshake_header.handshake_type:
            print("client_hello")

        elif Define().define_handshake_type["server_hello"] == handshake_header.handshake_type:
            handshake = self.Server_Hello_Analyze(str[point_length:  point_length + int.from_bytes(
                handshake_header.handshak_length, 'big')])
            point_length = point_length + int.from_bytes(
                handshake_header.handshak_length, 'big')

        elif Define().define_handshake_type["certificate"] == handshake_header.handshake_type:
            handshake = self.Certficate(str[point_length:  point_length + int.from_bytes(
                handshake_header.handshak_length, 'big')])
            point_length = point_length + int.from_bytes(
                handshake_header.handshak_length, 'big')

        elif Define().define_handshake_type["server_key_exchange"] == handshake_header.handshake_type:
            print("server_key_exchange")
            point_length = point_length + int.from_bytes(
                handshake_header.handshak_length, 'big')

        elif Define().define_handshake_type["certificate_request"] == handshake_header.handshake_type:
            print("certificate_request")
            point_length = point_length + int.from_bytes(
                handshake_header.handshak_length, 'big')

        elif Define().define_handshake_type["server_hello_done"] == handshake_header.handshake_type:
            print("server_hello_done")
            self.done = 1
            point_length = point_length + int.from_bytes(
                handshake_header.handshak_length, 'big')

        elif Define().define_handshake_type["certificate_verify"] == handshake_header.handshake_type:
            print("certificate_verify")
            point_length = point_length + int.from_bytes(
                handshake_header.handshak_length, 'big')

        elif Define().define_handshake_type["client_key_exchange"] == handshake_header.handshake_type:
            print("client_key_exchange")
            point_length = point_length + int.from_bytes(
                handshake_header.handshak_length, 'big')

        elif Define().define_handshake_type["finished"] == handshake_header.handshake_type:
            print("finished")
            point_length = point_length + int.from_bytes(
                handshake_header.handshak_length, 'big')

        else:
            print("handshake_type err : %s" % handshake_header.handshake_type)

        return point_length

    def Server_Hello_Analyze(self, str):

        server_hello = Server_Hello()
        point_length = 0

        print("--Server_Hello_Analyze---")

        point_length, server_hello.handshak_version = self.Separate_Str(
            str, point_length, Define().define_size["handshak_version"])
        handshak_version_str = analyze_dict(
            server_hello.handshak_version, Define().define_protocol_version)
        print("handshak_version :  %s" % handshak_version_str)

        point_length, server_hello.random = self.Separate_Str(
            str, point_length, Define().define_size["random"])
        print("random :  %s" % server_hello.random)

        point_length, server_hello.session_id_length = self.Separate_Str(
            str, point_length, Define().define_size["session_id_length"])
        print("session_id_length : %d" % int.from_bytes(
            server_hello.session_id_length, 'big'))

        point_length, server_hello.session_id = self.Separate_Str(
            str, point_length,  int.from_bytes(server_hello.session_id_length, 'big'))
        print("session_id : %s" % server_hello.session_id_length)

        point_length, server_hello.cipher_suite = self.Separate_Str(
            str, point_length, Define().define_size["cipher_suite"])
        print("cipher_suite : %s" % analyze_dict(server_hello.cipher_suite, Define().define_cipher_suite))

        point_length, server_hello.compression_method = self.Separate_Str(
            str, point_length, Define().define_size["compression_method"])
        print("compression_method : %s" % server_hello.compression_method)

        point_length, server_hello.extension_length = self.Separate_Str(
            str, point_length,  Define().define_size["extension_length"])
        print("extension_length : %d" % int.from_bytes(
            server_hello.extension_length, 'big'))

        point_length, server_hello.extensions = self.Separate_Str(
            str, point_length, int.from_bytes(
                server_hello.extension_length, 'big'))
        print("extensions : %s" % server_hello.extensions)

    def Certficate(self, str):
        certificate = Certificate()
        point_length = 0

        print("--Certificate---")

        point_length, certificate.certificate_struct_length = self.Separate_Str(
            str, point_length, Define().define_size["certificate_struct_length"])
        print("certificate_struct_length: %d" % int.from_bytes(
            certificate.certificate_struct_length, 'big'))

        point_length, certificate.certificate_length = self.Separate_Str(
            str, point_length, Define().define_size["certificate_length"])
        print("certificate_length: %d" % int.from_bytes(
            certificate.certificate_length, 'big'))

        point_length, certificate.certificate = self.Separate_Str(
            str, point_length, int.from_bytes(
                certificate.certificate_length, 'big'))
        print("certificate : %s" % certificate.certificate.hex())


def analyze_dict(data, dict):
    result = None
    for key, val in dict.items():
        if data == val:
            result = key
    return result


def main():
    port = 443
    destination_ip = "127.0.0.1"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((destination_ip, port))
        except ConnectionRefusedError as err:
            print(err)
            return
        print("tcp connected")
        tls_record_layer = TLS_Record_Layer()
        client_hello = Client_Hello()
        client_hello.cipher_suites = Define().define_cipher_suite["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]
        client_hello.extensions = client_hello.Extension_byte()
        client_hello.Client_Hello_len()
        handshake_header = Handshake_Header()
        handshake_header.handshake_type = Define().define_handshake_type["client_hello"]
        handshake_header.Handshake_Header_len(client_hello.Client_Hello_byte())
        tls_record_layer.TLS_Record_Layer_len(
            handshake_header.Handshake_Header_byte() + client_hello.Client_Hello_byte())

        tls_byte = tls_record_layer.TLS_Record_Layer_byte() + handshake_header.Handshake_Header_byte() + \
            client_hello.Client_Hello_byte()

        sock.send(tls_byte)

        tls_recv = TLS_Analyze()
        recv_data = sock.recv(1024)
        point_length = 0
        while tls_recv.done == 0: # 0 is completed
            print("---------------------------------------------------------------------")
            point_length = tls_recv.Analyze_Packet(recv_data,point_length)


if __name__ == '__main__':
    main()
