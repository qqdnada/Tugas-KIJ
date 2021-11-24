import uuid
import logging
import base64

from queue import Queue

class Chat:
    def __init__(self):
        self.sessions = {}
        self.users = {}
        self.users['nada'] = {
            'nama': 'Qatrunada Qori Darwati',
            'password': 'its',
            'public_key': "",
            'keys': {},
            'incoming': {},
            'outgoing': {}
        }
        self.users['anisa'] = {
            'nama': 'Anisa Aurafitri',
            'password': 'its',
            'public_key': "",
            'keys': {},
            'incoming': {},
            'outgoing': {}
        }
    def proses(self, data):
        d = data.split(" ")
        try:
            command = d[0].strip()

            if (command == 'auth'):
                username = d[1].strip()
                password = d[2].strip()
                public_key = str.encode(d[3].strip())

                logging.warning("AUTH: auth {} {}".format(username, password))
                return self.autentikasi_user(username, password, public_key)

            elif (command == 'send'):
                sessionid = d[1].strip()
                usernameto = d[2].strip()
                message = d[3].strip()
                # message =""
                # for m in d[3:]:
                #     message = "{} {}".format(message, m)
                usernamefrom = self.sessions[sessionid]['username']

                logging.warning("SEND: session {} send message from {} to {}".format(sessionid, usernamefrom,usernameto))
                return self.send_message(sessionid, usernamefrom, usernameto, message)

            elif (command == 'key'):
                sessionid = d[1].strip()
                usernameto = d[2].strip()
                usernamefrom = self.sessions[sessionid]['username']

                logging.warning("KEY: session {} from {} request public key to {}".format(sessionid, usernamefrom, usernameto))
                return self.get_publickey(usernameto)

            elif (command == 'check'):
                sessionid = d[1].strip()
                usernameto = d[2].strip()
                usernamefrom = self.sessions[sessionid]['username']

                logging.warning("KEY: session {} from {} check key to {}".format(sessionid, usernamefrom, usernameto))
                return self.check_key(usernamefrom, usernameto)

            elif (command == 'sendkey'):
                sessionid = d[1].strip()
                usernameto = d[2].strip()
                usernamefrom = self.sessions[sessionid]['username']

                keys = []
                for k in d[3:19]:
                    keys.append(k)

                logging.warning("KEY: session {} from {} send DES key to {}".format(sessionid, usernamefrom, usernameto))
                return self.set_key(usernamefrom, usernameto, keys)

            elif (command == 'inbox'):
                sessionid = d[1].strip()
                username = self.sessions[sessionid]['username']

                logging.warning("INBOX: {}".format(sessionid))
                return self.get_inbox(username)

            else:
                return {'status': 'ERROR', 'message': '**Protocol Tidak Benar'}
        except KeyError:
            return {'status': 'ERROR', 'message': 'Informasi tidak ditemukan'}
        except IndexError:
            return {'status': 'ERROR', 'message': '--Protocol Tidak Benar'}

    def autentikasi_user(self, username, password, public_key):
        if (username not in self.users):
            return {'status': 'ERROR', 'message': 'User Tidak Ada'}
        if (self.users[username]['password'] != password):
            return {'status': 'ERROR', 'message': 'Password Salah'}

        public_key = base64.b64decode(public_key)

        public_file = open('public/' + username + '-public_key.pem', 'wb')
        public_file.write(public_key)

        self.users[username]['public_key'] = 'public/' + username + '-public_key.pem'
        print(self.users[username]['public_key'])

        tokenid = str(uuid.uuid4())
        self.sessions[tokenid] = {'username': username, 'userdetail': self.users[username]}

        return {'status': 'OK', 'tokenid': tokenid}

    def check_key(self, username, usernameto):
        if (username not in self.users):
            return False

        if usernameto in self.users[username]['keys'].keys():
            key = self.users[username]['keys'][usernameto]
            return {'status': 'OK', 'key': key}
        else:
            return {'status': 'Key not found'}

    def get_user(self, username):
        if (username not in self.users):
            return False

        return self.users[username]

    def get_publickey(self, username):
        if (username not in self.users):
            return False

        public_file = open(self.users[username]['public_key'], 'rb').read()
        public_key = base64.b64encode(public_file).decode()

        return {'status': 'OK', 'public_key': public_key}

    def set_key(self, username_from, username_to, keys):
        if (username_to not in self.users):
            return False

        self.users[username_to]['keys'][username_from] = keys

        return {'status': 'OK', 'keys': keys, 'message': 'Key sent'}

    def send_message(self, sessionid, username_from, username_dest, message):
        if (sessionid not in self.sessions):
            return {'status': 'ERROR', 'message': 'Session Tidak Ditemukan'}

        s_fr = self.get_user(username_from)
        s_to = self.get_user(username_dest)

        if (s_fr == False or s_to == False):
            return {'status': 'ERROR', 'message': 'User Tidak Ditemukan'}

        message = {'msg_from': s_fr['nama'], 'msg_to': s_to['nama'], 'msg': message}
        outqueue_sender = s_fr['outgoing']
        inqueue_receiver = s_to['incoming']

        try:
            outqueue_sender[username_from].put(message)
        except KeyError:
            outqueue_sender[username_from] = Queue()
            outqueue_sender[username_from].put(message)
        try:
            inqueue_receiver[username_from].put(message)
        except KeyError:
            inqueue_receiver[username_from] = Queue()
            inqueue_receiver[username_from].put(message)

        return {'status': 'OK', 'message': 'Message Sent'}

    def get_inbox(self, username):
        s_fr = self.get_user(username)
        incoming = s_fr['incoming']
        msgs = {}
        for users in incoming:
            msgs[users] = []
            while not incoming[users].empty():
                msgs[users].append(s_fr['incoming'][users].get_nowait())

        return {'status': 'OK', 'messages': msgs}


if __name__ == "__main__":
    c = Chat()

    sesi = c.proses("auth nada its")
    tokenid = sesi['tokenid']

    print(c.proses("send {} nada hello gimana kabarnya son ".format(tokenid)))
    print(c.proses("send {} nada hello gimana kabarnya sis ".format(tokenid)))

    # print("isi mailbox dari nada")
    # print(c.get_inbox('anisa'))

    print("isi mailbox dari nada")
    print(c.proses("inbox {}".format(tokenid)))

    print("isi mailbox dari nada")
    print(c.proses("inbox {}".format(tokenid)))

    print("isi mailbox dari nada")
    print(c.proses("inbox {}".format(tokenid)))