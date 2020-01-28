class TLS_Analyze:
    def __init__(self):
        Define()

    def Define(self):
        self.contenttype = {"change_cipher_spec":'\x14',"alert":'\x15',"handshake":'\x16',"application_data":'\x17'}
