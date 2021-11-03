from Crypto.Cipher import DES
from Crypto.Util.Padding import pad

import base64

key = b'1234ABCD'

class DataEncryptionStandard:

    # def __init__(self):

    def encrypt(self, msg):
        cipher = DES.new(key, DES.MODE_ECB)
        padded_text = pad(msg.encode(), 16)
        en = cipher.encrypt(padded_text)
        return en
        # cipher = DES.new(key, DES.MODE_EAX)
        # nonce = cipher.nonce
        # ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
        # return nonce, ciphertext, tag

    def decrypt(self, msg):
        cipher = DES.new(key, DES.MODE_ECB)
        decrypted_text = cipher.decrypt(msg)

        return decrypted_text.decode()

    # def decrypt(self, nonce, ciphertext, tag):
    #     cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    #     plaintext = cipher.decrypt(ciphertext)
    #
    #     try:
    #         cipher.verify(tag)
    #         return plaintext.decode('ascii')
    #     except:
    #         return False

if __name__ == "__main__":
    des = DataEncryptionStandard()

    ciphertext = des.encrypt("ello")
    # nonce, ciphertext, tag = des.encrypt(input('Enter a message: '))
    # plaintext = des.decrypt(nonce, ciphertext, tag)
    #
    print(f'Cipher text: {ciphertext}')
    change = base64.b64encode(ciphertext).decode()
    print(change)
    # print(type(str(ciphertext, 'UTF-8')))

    #
    # if not plaintext:
    #     print('Message is corrupted')
    # else:

    # plaintext = des.decrypt(ciphertext)
    # print(f'Plain text: {plaintext}')