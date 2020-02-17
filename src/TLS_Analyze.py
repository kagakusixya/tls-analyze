import socket
from time import sleep

from Define import *
from TLS_Struct import *


class TLS_Analyze:

    def Separate_Str(self, str, point_length, len):
        separate_data = b''
        for i in range(len):
            separate_data = separate_data + str[i +
                                                point_length].to_bytes(1, 'big')
        point_length = len + point_length
        return point_length, separate_data

    def Analyze_Packet(self, str):

        tls_record_layer = TLS_Record_Layer()
        handshake_header = Handshake_Header()
        point_length = 0

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
        client_hello.extensions = client_hello.Extension_byte()
        client_hello.Client_Hello_len()
        handshake_header = Handshake_Header()
        handshake_header.Handshake_Header_len(client_hello.Client_Hello_byte())
        tls_record_layer.TLS_Record_Layer_len(
            handshake_header.Handshake_Header_byte() + client_hello.Client_Hello_byte())

        tls_byte = tls_record_layer.TLS_Record_Layer_byte() + handshake_header.Handshake_Header_byte() + \
            client_hello.Client_Hello_byte()

        sock.send(tls_byte)

        recv_data = sock.recv(2048)
        print("-----recive data-----")
        tls_recv = TLS_Analyze()
        tls_recv.Analyze_Packet(recv_data)

        sleep(3)


if __name__ == '__main__':
    main()
