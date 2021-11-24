import socket
import json
import base64

from des import DataEncryptionStandard
from rsa import RSAAlgorithm

des = DataEncryptionStandard()
rsa = RSAAlgorithm()

TARGET_IP = "127.0.0.1"
TARGET_PORT = 8889

class ChatClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = (TARGET_IP,TARGET_PORT)
        self.sock.connect(self.server_address)
        self.tokenid = ""
        self.private = "private_key.pem"
        self.public = "public_key.pem"
        self.keys = {}

        rsa.export_private_key(rsa.keypair, self.private)
        rsa.export_public_key(rsa.public_key, self.public)
        # self.key = des.keygeneration()
        # self.key_decrypt = self.key[::-1]
    def proses(self,cmdline):
        d = cmdline.split(" ")
        try:
            command = d[0].strip()
            if (command == 'auth'):
                username = d[1].strip()
                password = d[2].strip()
                return self.login(username,password)
            elif (command=='send'):
                usernameto = d[1].strip()
                message = ""
                for m in d[2:]:
                   message = "{} {}" . format(message,m)

                des_key = []
                if (usernameto in self.keys.keys()):
                    des_key = self.keys[usernameto]
                else:
                    if (self.check_key(usernameto)):
                        des_key = self.check_key(usernameto)
                        print(des_key)

                        file = open("private_key.pem", "r").read()

                        deskey = []
                        for k in des_key:
                            decrypt = base64.b64decode(k.encode())
                            plain = rsa.decrypt(file, decrypt)
                            deskey.append(plain.decode())
                            print(plain.decode())
                        self.keys[usernameto] = deskey
                        des_key = deskey
                    else:
                        des_key = des.keygeneration()
                        print(des_key)
                        self.keys[usernameto] = des_key
                        self.sendkey(usernameto)

                print(self.keys)

                hexmsg = des.ascii2hex(message)
                ciphertext = des.encrypts(hexmsg, des_key)

                # return self.sendmessage(usernameto, message)
                return self.sendmessage(usernameto, ciphertext)
            elif (command == 'inbox'):
                return self.inbox()
            else:
                return "*Maaf, command tidak benar"
        except IndexError:
                return "-Maaf, command tidak benar"
    def sendstring(self,string):
        try:
            self.sock.sendall(string.encode())
            receivemsg = ""
            while True:
                data = self.sock.recv(64)
                # print("diterima dari server",data)
                if (data):
                    receivemsg = "{}{}" . format(receivemsg,data.decode())  #data harus didecode agar dapat di operasikan dalam bentuk string
                    if receivemsg[-4:]=='\r\n\r\n':
                        # print("end of string")
                        return json.loads(receivemsg)
        except:
            self.sock.close()
            return {'status': 'ERROR', 'message': 'Gagal'}
    def login(self,username,password):

        public_file = open(self.public, 'rb').read()
        public_key = base64.b64encode(public_file).decode()

        string = "auth {} {} {}\r\n" . format(username,password,public_key)
        result = self.sendstring(string)
        if result['status'] == 'OK':
            self.tokenid = result['tokenid']
            return "username {} logged in, token {} " .format(username,self.tokenid)
        else:
            return "Error, {}" . format(result['message'])
    def sendmessage(self,usernameto="xxx",message="xxx"):
        if (self.tokenid == ""):
            return "Error, not authorized"
        string = "send {} {} {}\r\n" . format(self.tokenid,usernameto,message)
        print(string)
        result = self.sendstring(string)
        if result['status'] == 'OK':
            return "message sent to {}" . format(usernameto)
        else:
            return "Error, {}" . format(result['message'])
    def sendkey(self, usernameto):
        if (self.tokenid == ""):
            return "Error, not authorized"

        string = "key {} {}\r\n".format(self.tokenid,usernameto)
        result = self.sendstring(string)

        if result['status'] == 'OK':

            public_key = base64.b64decode(result['public_key'].encode())

            public_file = open(usernameto + '-public_key.pem', 'wb')
            public_file.write(public_key)
            public_file.close()

        else:
            return "Error, {}" . format(result['message'])

        des_key = []
        file = open(usernameto + "-public_key.pem", "r").read()

        for k in self.keys[usernameto]:
            cipher = rsa.encrypt(file, str.encode(k))
            des_key.append(base64.b64encode(cipher).decode())

        string_key = " ".join(map(str, des_key))
        string = "sendkey {} {} {} \r\n".format(self.tokenid,usernameto, string_key)
        print(string)

        result = self.sendstring(string)
        if result['status'] == 'OK':
            print(result['keys'])
            return "DES key sent to {}".format(usernameto)
        else:
            return "Error, {}".format(result['message'])

    def check_key(self,usernameto):
        if (self.tokenid == ""):
            return "Error, not authorized"
        string = "check {} {}\r\n" . format(self.tokenid,usernameto)
        result = self.sendstring(string)
        if result['status'] == 'OK':
            return result['key']
        else:
            return False

    def inbox(self):
        if (self.tokenid == ""):
            return "Error, not authorized"
        string = "inbox {} \r\n" . format(self.tokenid)
        result = self.sendstring(string)
        if result['status'] == 'OK':
            for user in result['messages']:
                key_decrypt = self.keys[user][::-1]
                for msg in result['messages'][user]:
                    res = des.encrypts(msg['msg'], key_decrypt)
                    msg['msg'] = des.hex2ascii(res)
            return "{}" . format(json.dumps(result['messages']))
        else:
            return "Error, {}" . format(result['message'])

if __name__=="__main__":
    cc = ChatClient()
    while True:
        cmdline = input("Command {}:" . format(cc.tokenid))
        print(cc.proses(cmdline))

