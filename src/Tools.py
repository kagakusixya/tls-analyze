import base64


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
        f = open('crt/' + name + '.crt', 'x')

        f.write(str)

        f.close()