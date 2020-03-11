import socket

from TLS_Analyze import *

from Define import *
from TLS_Struct import *
from TLS_Debug import *
from Tools import *

def main():
    port = 443
    destination_ip = "127.0.0.1"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((destination_ip, port))
        except ConnectionRefusedError as err:
            print(err)
            return
        tls_record_layer = TLS_Record_Layer()
        client_hello = Client_Hello()
        client_hello.cipher_suites = Define(
        ).define_cipher_suite["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]
        client_hello.extensions = client_hello.Extension_byte()
        client_hello.Client_Hello_len()
        handshake_header = Handshake_Header()
        handshake_header.handshake_type = Define(
        ).define_handshake_type["client_hello"]
        handshake_header.Handshake_Header_len(client_hello.Client_Hello_byte())
        tls_record_layer.TLS_Record_Layer_len(
            handshake_header.Handshake_Header_byte() + client_hello.Client_Hello_byte())

        tls_byte = tls_record_layer.TLS_Record_Layer_byte() + handshake_header.Handshake_Header_byte() + \
            client_hello.Client_Hello_byte()

        sock.send(tls_byte)

        tls_recv = TLS_Analyze()
        point_length = 0
        tls_basics = {}
        recv_data = b""
        while tls_recv.done != 1:  # 0 is completed
            if tls_recv.done == 2:
                recv_data = recv_data + sock.recv(6000)
                tls_recv.done = 0
            point_length, tls_basic = tls_recv.Analyze_Packet(
                recv_data, point_length)
            tls_basics[analyze_dict(tls_basic.handshake_header.handshake_type, Define(
            ).define_handshake_type)] = tls_basic

        TLS_Debug().Show(tls_basics["server_key_exchange"])

if __name__ == '__main__':
    main()
