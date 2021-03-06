from Define import *
from TLS_Struct import *
from Tools import separate_str

class TLS_Analyze:
    def __init__(self):
        self.done = 0
        self.point_length = 0
        self.tls_basics = {}
        # 0 is no done
        # 1 is done
        # -1 is alert


    def Analyze_Packet(self, str):

        tls_record_layer = TLS_Record_Layer()

        self.point_length, tls_record_layer.content_type = separate_str(
            str, self.point_length, Define().define_size["content_type"])

        self.point_length, tls_record_layer.version = separate_str(
            str, self.point_length, Define().define_size["version"])

        self.point_length, tls_record_layer.length = separate_str(
            str, self.point_length, Define().define_size["length"])

        self.data = str[self.point_length:self.point_length+int.from_bytes(tls_record_layer.length, 'big')]

        #encrypt

        local_point_length,tls_basic = self.TLS_Content_If(tls_record_layer, self.data)
        self.point_length = int.from_bytes(tls_record_layer.length, 'big') + self.point_length
        return tls_basic

    def TLS_Content_If(self, tls_record_layer, str):
        point_length = 0

        if Define().define_content_type["change_cipher_spec"] == tls_record_layer.content_type:
            pass
        elif Define().define_content_type["alert"] == tls_record_layer.content_type:
            pass
        elif Define().define_content_type["handshake"] == tls_record_layer.content_type:
            tls_basic = TLS_Handshake_Basic()
            tls_basic.tls_record_layer = tls_record_layer

            point_length, tls_basic.handshake_header.handshake_type = separate_str(
                str, point_length, Define().define_size["handshake_type"])

            point_length, tls_basic.handshake_header.handshak_length = separate_str(
                str, point_length, Define().define_size["handshak_length"])

            str = str[point_length:point_length+int.from_bytes(tls_basic.handshake_header.handshak_length, 'big')]

            point_length, tls_basic = self.TLS_Handshake_If(tls_basic, str)

        elif Define().define_content_type["application_data"] == tls_record_layer.content_type:
            pass
        else:
            print("content_type err : %s" %
                  tls_basic.tls_record_layer.content_type)

        return point_length , tls_basic

    def TLS_Handshake_If(self, tls_basic, str):
        point_length = 0

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
            tls_basic.payload = self.Server_Key_Exchange(
                str[point_length: point_length + int.from_bytes(tls_basic.handshake_header.handshak_length, 'big')])
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

        return point_length,tls_basic

    def Server_Hello_Analyze(self, str):

        server_hello = Server_Hello()
        point_length = 0

        point_length, server_hello.handshak_version = separate_str(
            str, point_length, Define().define_size["handshak_version"])

        point_length, server_hello.random = separate_str(
            str, point_length, Define().define_size["random"])

        point_length, server_hello.session_id_length = separate_str(
            str, point_length, Define().define_size["session_id_length"])

        point_length, server_hello.session_id = separate_str(
            str, point_length,  int.from_bytes(server_hello.session_id_length, 'big'))

        point_length, server_hello.cipher_suite = separate_str(
            str, point_length, Define().define_size["cipher_suite"])

        point_length, server_hello.compression_method = separate_str(
            str, point_length, Define().define_size["compression_method"])

        point_length, server_hello.extension_length = separate_str(
            str, point_length,  Define().define_size["extension_length"])

        point_length, server_hello.extensions = separate_str(
            str, point_length, int.from_bytes(
                server_hello.extension_length, 'big'))
        return server_hello

    def Certficate(self, str):
        certificate = Certificate()
        point_length = 0

        point_length, certificate.certificate_struct_length = separate_str(
            str, point_length, Define().define_size["certificate_struct_length"])

        while point_length < len(str):
            point_length, certificate.certificate_length = separate_str(
                str, point_length, Define().define_size["certificate_length"])

            point_length, crt = separate_str(
                str, point_length, int.from_bytes(certificate.certificate_length, 'big'))

            certificate.certificate.append(crt)

        return certificate

    def Server_Key_Exchange(self, str):
        server_key_exchange = Server_Key_Exchange()
        point_length = 0

        point_length, server_key_exchange.curve_type = separate_str(
            str, point_length, Define().define_size["curve_type"])

        point_length, server_key_exchange.named_curve = separate_str(
            str, point_length, Define().define_size["named_curve"])

        point_length, server_key_exchange.pubkey_length = separate_str(
            str, point_length, Define().define_size["pubkey_length"])

        point_length, server_key_exchange.pubkey = separate_str(
            str, point_length, int.from_bytes(
                server_key_exchange.pubkey_length, 'big'))

        point_length, server_key_exchange.algorithms_hash = separate_str(
            str, point_length, Define().define_size["algorithms_hash"])

        point_length, server_key_exchange.algorithms_signature = separate_str(
            str, point_length, Define().define_size["algorithms_signature"])

        point_length, server_key_exchange.signature_length = separate_str(
            str, point_length, Define().define_size["signature_length"])

        point_length, server_key_exchange.signature = separate_str(
            str, point_length, int.from_bytes(
                server_key_exchange.signature_length, 'big'))

        return server_key_exchange

    def Finished(self, str):

        finished = Finished()
        self.finished_verify_data = separate_str(str,point_length,Define().define_size["finished_verify_data"])
