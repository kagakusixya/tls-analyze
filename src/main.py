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

        tls_basic = TLS_Basic()
        #client_hello
        tls_basic.payload = Client_Hello()
        tls_basic.payload.cipher_suites = Define(
        ).define_cipher_suite["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]
        tls_basic.payload.extensions = tls_basic.payload.Extension_byte()

        #handshake_header
        tls_basic.handshake_header = Handshake_Header()
        tls_basic.handshake_header.handshake_type = Define(
        ).define_handshake_type["client_hello"]

        tls_basic.setlen()

        tls_byte = tls_basic.tls_record_layer.TLS_Record_Layer_byte() + tls_basic.handshake_header.Handshake_Header_byte() + \
            tls_basic.payload.byte()

        TLS_Debug().Show(tls_basic)

        sock.send(tls_byte)

        tls_analyze = TLS_Analyze()

        sock.settimeout(0.5)
        recv_segment = b''
        recv_all = b''
        while 1 :
            try:
                recv_segment = sock.recv(1500)
            except socket.timeout :
                break
            recv_all = recv_all  + recv_segment

        while tls_analyze.done == 0:  # 0 is completed

            tls_basic = tls_analyze.Analyze_Packet(recv_all)

            TLS_Debug().Show(tls_basic)

            tls_analyze.tls_basics[analyze_dict(tls_basic.handshake_header.handshake_type, Define(
            ).define_handshake_type)] = tls_basic

if __name__ == '__main__':
    main()
