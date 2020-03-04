import base64

class Tools:
    def Create_Pem(self,str):

        str = base64.b64encode(str).decode()
        i = 0
        print("-----BEGIN CERTIFICATE-----")
        for c in str:
            print(c,end="")
            i = i + 1
            if i%64 == 0:
                print("")
        print("")
        print("-----END CERTIFICATE-----")
