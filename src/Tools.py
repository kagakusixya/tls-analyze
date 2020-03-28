from Define import *

import base64
from tinyec import ec
from tinyec import registry
import secrets


class Tools:
    def Create_Pem(self, str):

        str = base64.b64encode(str).decode()
        i = 0
        crt = "-----BEGIN CERTIFICATE-----\n"
        for c in str:
            crt = crt + c
            i = i + 1
            if i % 64 == 0:
                crt = crt + "\n"
        crt = crt + "\n"
        crt = crt + "-----END CERTIFICATE-----\n"
        return crt

    def Out_Crtificate(self, str, name):
        try:
            f = open('crt/' + name + '.crt', 'x')
        except FileExistsError as e:
            print(e)
            print("Out_Crtificate err: maybe this name is already used.")
            return
        f.write(str)

        f.close()

    def ECDHE_Key_RFC5480_Format(self):
        return b'\x04' + self.pubkey.x.to_bytes(32, 'big').hex() + self.pubkey.y.to_bytes(32, 'big').hex()

    def ECDHE_Key_Point(self, rfc5480_pubkey, curve_type_byte):

        curve_type_str = analyze_dict(curve_type_byte,Define().define_named_curve)
        curve_type = registry.get_curve(curve_type_str)

        x_byte = rfc5480_pubkey[1:33]
        x = int.from_bytes(x_byte, 'big')

        y_byte = rfc5480_pubkey[33:65]
        y = int.from_bytes(y_byte, 'big')

        pubkey = ec.Point(curve_type, x, y)
        return pubkey

    def ECDHE(self, server_pubkey, curve_type_byte):

        curve_type_str = analyze_dict(curve_type_byte,Define().define_named_curve)

        curve = registry.get_curve(curve_type_str)

        self.privkey = secrets.randbelow(curve.field.n)
        self.pubkey = self.privkey * curve.g

        self.sharekey = self.privkey * server_pubkey

def analyze_dict(data, dict):
    result = None
    for key, val in dict.items():
        if data == val:
            result = key
    return result
