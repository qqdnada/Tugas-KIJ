from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
import base64

class RSAAlgorithm:

    def __init__(self):
        self.keypair = RSA.generate(1024)
        self.public_key = self.keypair.publickey()

    def export_private_key(self, private_key, file):

        with open(file, "wb") as file:
            file.write(private_key.exportKey('PEM'))
            file.close()

    def export_public_key(self, public_key, file):

        with open(file, "wb") as file:
            file.write(public_key.exportKey('PEM'))
            file.close()

    def encrypt(self, public_key, message):

        rsa_public_key = RSA.importKey(public_key)
        rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
        encrypted_text = rsa_public_key.encrypt(message)

        return encrypted_text

    def decrypt(self, private_key, message):

        rsa_private_key = RSA.importKey(private_key)
        rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
        decrypted_text = rsa_private_key.decrypt(message)

        return  decrypted_text

if __name__ == "__main__":
    rsa = RSAAlgorithm()

    # rsa.export_private_key(rsa.keypair, 'private_key.pem')
    # rsa.export_public_key(rsa.public_key, 'public_key.pem')

    fpu = open("public_key.pem", "r").read()
    print(fpu)

    cipher = rsa.encrypt(fpu, str.encode("Hello World!"))
    print(type(cipher), cipher)

    # cipher = base64.b64encode(cipher).decode()

    # print(type(cipher), cipher)
    # print(type(base64.b64encode(cipher).decode()), base64.b64encode(cipher))

    # cipher_text = cipher.encode()
    # cipher_text = base64.b64decode(cipher_text)

    # print(type(cipher_text), cipher_text)

    fpr = open("private_key.pem", "r")
    plain = rsa.decrypt(fpr.read(), cipher)

    print(plain)

