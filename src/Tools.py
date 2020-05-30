from Define import *

import random
import base64
from tinyec import ec
from tinyec import registry
import secrets
import hashlib
from Crypto.Hash import HMAC, SHA256


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

    def Separate_Certificate(self, str):
        certificate_format = Certificate_Format()

        return certificate_format

    def Out_Certificate(self, str, name):
        try:
            f = open('crt/' + name + '.crt', 'x')
        except FileExistsError as e:
            print(e)
            print("Out_Crtificate err: maybe this name is already used.")
            return
        f.write(str)

        f.close()

    def ECDHE_Key_RFC5480_Format(self):
        return b'\x04' + self.pubkey.x.to_bytes(32, 'big') + self.pubkey.y.to_bytes(32, 'big')

    def ECDHE_Key_Point(self, rfc5480_pubkey, curve_type_byte):

        curve_type_str = analyze_dict(
            curve_type_byte, Define().define_named_curve)
        curve_type = registry.get_curve(curve_type_str)

        x_byte = rfc5480_pubkey[1:33]
        x = int.from_bytes(x_byte, 'big')

        y_byte = rfc5480_pubkey[33:65]
        y = int.from_bytes(y_byte, 'big')

        pubkey = ec.Point(curve_type, x, y)
        return pubkey

    def ECDHE(self, server_pubkey, curve_type_byte):

        curve_type_str = analyze_dict(
            curve_type_byte, Define().define_named_curve)

        curve = registry.get_curve(curve_type_str)

        self.privkey = secrets.randbelow(curve.field.n)
        self.pubkey = self.privkey * curve.g

        self.sharekey = self.privkey * server_pubkey

    def P_hash(self, algo, secret, seed, size):
        #data = secret + seed
        hmac = HMAC.new(secret, digestmod=SHA256)
        #hmac = hashlib.sha256()
        hmac.update(seed)
        # hmac.update(data)  # A(0)
        a = hmac.digest()
        # a = hmac.digest()  # A(1)
        result = b''
        i = 1
        #sum = b""
        #i = 0
        hmac = HMAC.new(secret, digestmod=SHA256)
        b_hmac = HMAC.new(secret, digestmod=SHA256)
        hmac.update(a + seed)
        b_hmac.update(a)
        result = result + hmac.digest()
        a = result
        b = b_hmac.digest()

        hmac = HMAC.new(secret, digestmod=SHA256)
        hmac.update(b + seed)
        result = result + hmac.digest()
        a = result
        return result[:size]

    def PRF(self, secret, label, seed, size):
        return self.P_hash("sha256", secret, label + seed, size)

    def Create_Premaster_Secret(self, version):
        return version + make_random(46)


def analyze_dict(data, dict):
    result = None
    for key, val in dict.items():
        if data == val:
            result = key
    return result


def separate_str(str, point_length, len):
    separate_data = b''
    for i in range(len):
        separate_data = separate_data + str[i +
                                            point_length].to_bytes(1, 'big')
    point_length = len + point_length
    return point_length, separate_data


def make_random(size):
    sum = b""
    for i in range(size):
        x = random.randrange(256)
        sum = x.to_bytes(1, 'big') + bytes(sum)
    return sum


class Certificate_Format:
    def __init__(self):
        slef.size = 5

        self.title_length = b''
        self.title = b'ssh-rsa'
        self.e_length = b''
        self.e = b''
        self.n_length = b''
        self.n = b''

    def byte(self):
        data = self.title_length + self.title + \
            self.e_length + self.e + self.n_length + self.n
        return byte_data


class Key_Block:
    def __init__(self,str):
        print(str)
        self.client_write_MAC_key = b''
        self.server_write_MAC_key = b''
        self.client_write_key = str[:16]
        print("client_write_key")
        print(self.client_write_key)
        self.server_write_key = str[16:32]
        print(self.server_write_key)
        self.client_write_IV = str[32:36]
        print(self.client_write_IV)
        self.server_write_IV = str[36:]
        print(len(self.server_write_IV))
    def byte(self):
        byte_data = self.client_write_MAC_key + self.server_write_MAC_key + \
            self.client_write_key + self.server_write_key + \
            self.client_write_IV + self.server_write_IV
