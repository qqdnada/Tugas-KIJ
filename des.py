class DataEncryptionStandard:

    # def __init__(self):
    #     self.key = "133457799BBCDFF1" # "AABB09182736CCDD"

    # hexadecimal to binary conversion
    def hex2bin(self, str):
        map = {
            '0': "0000",
            '1': "0001",
            '2': "0010",
            '3': "0011",
            '4': "0100",
            '5': "0101",
            '6': "0110",
            '7': "0111",
            '8': "1000",
            '9': "1001",
            'A': "1010",
            'B': "1011",
            'C': "1100",
            'D': "1101",
            'E': "1110",
            'F': "1111"
        }
        bin = ""
        for i in range(len(str)):
            bin = bin + map[str[i]]
        return bin

    # binary to hexadecimal conversion
    def bin2hex(self, str):
        map = {
            "0000": '0',
            "0001": '1',
            "0010": '2',
            "0011": '3',
            "0100": '4',
            "0101": '5',
            "0110": '6',
            "0111": '7',
            "1000": '8',
            "1001": '9',
            "1010": 'A',
            "1011": 'B',
            "1100": 'C',
            "1101": 'D',
            "1110": 'E',
            "1111": 'F'
        }
        hex = ""
        for i in range(0, len(str), 4):
            tmp = str[i:i + 4]
            hex = hex + map[tmp]
        return hex

    def dec2bin(self, n):
        binary = bin(n).replace("0b", "")
        if (len(binary) % 4):
            while len(binary) < 4:
                binary = "0" + binary

        return binary

    def ascii2hex(self, str):
        hex = "".join(["{:02x}".format(ord(c)) for c in str])
        return hex.upper()

    def hex2ascii(self, str):
        byte_array = bytearray.fromhex(str)
        return byte_array.decode()

    # permutation function to rearrange the bits
    def permute(self, str, arr):
        p = ""
        for i in range(len(arr)):
            p = p + str[arr[i] - 1]
        return p

    # left shift function
    def leftshift(self, str, shift):
        res = ""
        for i in range(shift):
            for j in range(len(str) - 1):
                res = res + str[j + 1]
            res = res + str[0]
            str = res
            res = ""
        return str

    # XOR Function
    def xor(self, a, b):
        res = ""
        for i in range(len(a)):
            if a[i] == b[i]:
                res = res + "0"
            else:
                res = res + "1"
        return res

    def keygeneration(self, key="133457799BBCDFF1"):
        # Permutated Choice One (PC-1)
        pc1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
               10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
               63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
               14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

        # schedule of left shift
        schedule = [1, 1, 2, 2, 2, 2, 2, 2,
                    1, 2, 2, 2, 2, 2, 2, 1]

        # Permutated Choice Two (PC-2)
        pc2 = [14, 17, 11, 24, 1, 5,
               3, 28, 15, 6, 21, 10,
               23, 19, 12, 4, 26, 8,
               16, 7, 27, 20, 13, 2,
               41, 52, 31, 37, 47, 55,
               30, 40, 51, 45, 33, 48,
               44, 49, 39, 56, 34, 53,
               46, 42, 50, 36, 29, 32]

        k = self.hex2bin(key)
        k = self.permute(k, pc1)
        c = k[0:28]
        d = k[28:56]

        round_key = []

        for i in range(16):
            c = self.leftshift(c, schedule[i])
            d = self.leftshift(d, schedule[i])

            round_key.append(self.bin2hex(self.permute(c + d, pc2)))
            # print(self.bin2hex(round_key[i]), self.hex2bin(self.bin2hex(round_key[i])))

        return round_key

    def encrypt(self, msg, subkey):

        # Initial Permutation (IP)
        ip = [58, 50, 42, 34, 26, 18, 10, 2,
              60, 52, 44, 36, 28, 20, 12, 4,
              62, 54, 46, 38, 30, 22, 14, 6,
              64, 56, 48, 40, 32, 24, 16, 8,
              57, 49, 41, 33, 25, 17, 9, 1,
              59, 51, 43, 35, 27, 19, 11, 3,
              61, 53, 45, 37, 29, 21, 13, 5,
              63, 55, 47, 39, 31, 23, 15, 7]

        msg = self.hex2bin(msg)

        # Initial Permutation
        msg = self.permute(msg, ip)

        # Splitting
        l = msg[0:32]
        r = msg[32:64]

        # Expansion Permutation (E)
        e = [32, 1, 2, 3, 4, 5,
             4, 5, 6, 7, 8, 9,
             8, 9, 10, 11, 12, 13,
             12, 13, 14, 15, 16, 17,
             16, 17, 18, 19, 20, 21,
             20, 21, 22, 23, 24, 25,
             24, 25, 26, 27, 28, 29,
             28, 29, 30, 31, 32, 1]

        # S-box Table
        sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                 [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                 [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                 [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

                [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                 [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                 [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                 [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

                [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                 [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                 [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                 [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

                [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                 [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                 [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                 [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

                [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                 [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                 [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                 [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

                [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                 [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                 [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                 [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

                [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                 [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                 [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                 [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

                [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                 [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                 [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                 [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

        # Straight Permutation Table
        p = [16, 7, 20, 21,
             29, 12, 28, 17,
             1, 15, 23, 26,
             5, 18, 31, 10,
             2, 8, 24, 14,
             32, 27, 3, 9,
             19, 13, 30, 6,
             22, 11, 4, 25]

        # Round Function
        for i in range(16):
            # Expansion Permutation
            r_exp = self.permute(r, e)

            # XOR r_exp with round_key
            xor_r = self.xor(r_exp, self.hex2bin(subkey[i]))

            # Substitution
            sbx_r = ""
            for j in range(0, len(xor_r), 6):
                sbx = xor_r[j:j + 6]
                row = int(sbx[0] + sbx[5], 2)
                col = int(sbx[1:5], 2)

                n = sbox[j // 6][row][col]
                sbx_r = sbx_r + self.dec2bin(n)

            # Straight Permutation
            sbx_r = self.permute(sbx_r, p)

            # XOR sbx_r with left
            l = self.xor(l, sbx_r)

            # Swap left with right and vice versa
            if (i < 15):
                l, r = r, l

        # Combine
        combine = l + r

        # Inverse Initial Permutation
        iip = [40, 8, 48, 16, 56, 24, 64, 32,
               39, 7, 47, 15, 55, 23, 63, 31,
               38, 6, 46, 14, 54, 22, 62, 30,
               37, 5, 45, 13, 53, 21, 61, 29,
               36, 4, 44, 12, 52, 20, 60, 28,
               35, 3, 43, 11, 51, 19, 59, 27,
               34, 2, 42, 10, 50, 18, 58, 26,
               33, 1, 41, 9, 49, 17, 57, 25]

        # Final Permutation
        cipher = self.permute(combine, iip)
        return self.bin2hex(cipher)

    def padding(self, str):
        arr = []
        for i in range(0, len(str), 16):
            pad = str[i:i + 16]
            if len(pad) % 16 != 0:
                while len(pad) < 16:
                    pad = pad + "05"
            arr.append(pad)
        return arr

    def encrypts(self, message, subkey):
        strs = self.padding(message)
        cipher = ""
        for str in strs:
            cipher = cipher + self.encrypt(str, subkey)
        return cipher


if __name__ == "__main__":
    des = DataEncryptionStandard()

    hex = des.ascii2hex("hello world 12134")
    print(hex)

    subkey = des.keygeneration("AABB09182736CCDD")
    print(subkey)

    ciphertext = des.encrypts(hex, subkey)
    print(ciphertext)

    subkeyd = subkey[::-1]
    plaintext = des.encrypts(ciphertext, subkeyd)
    print(plaintext)

    asciis = des.hex2ascii(plaintext)
    print(asciis)