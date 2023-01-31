import hashlib
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class Person:
    q=0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
    a=0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
    # q = 37
    # a = 5    
    X = -1
    Y = -1
    s = -1
    k = b''
    cipher = None

    def getq(self):
        return self.q

    def geta(self):
        return self.a

    def pickX(self):
        self.X = random.randint(1, self.q)

    def getY(self):
        if self.X == -1:
            self.pickX()
        self.Y = pow(self.a, self.X, self.q)
        return self.Y

    def calcS(self, otherY):
        if self.X == -1:
            self.pickX()
        self.s = pow(otherY, self.X, self.q)

    def calcK(self):
        if self.s == -1:
            return
        self.k = hashlib.sha256(str(self.s).encode('utf-8')).digest()[:16]
        print("Got self.k")
        print(self.k)

    def encryptMessage(self, message):
        if self.cipher == None:
            if(self.k == b''):
                self.calcK()
            self.cipher = AES.new(self.k, AES.MODE_CBC)
        return self.cipher.encrypt(message)

def CBC_encrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(bytes(plaintext, 'utf8'), 16))
    return ciphertext

def CBC_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), 16)
    return plaintext

def main():
    # task 1
    print("*** Task 1 ***")
    Alice = Person()
    Bob = Person()
    # Alice and bob are people who share an a and q value

    Alice.pickX()
    Bob.pickX()

    Ya = Alice.getY()
    Yb = Bob.getY()

    Alice.calcS(Yb)
    Bob.calcS(Ya)

    Alice.calcK()
    Bob.calcK()

    m0 = b"Hi Bob!         "
    m1 = b"Hi Alice!       "
    c0 = Alice.encryptMessage(m0)
    c1 = Bob.encryptMessage(m1)

    print(c0)
    print(c1)
    print()

    # task 2-1
    print("*** Task 2-1 ***")
    Alice = Person()
    Bob = Person()

    Alice.pickX()
    Ya = Alice.getY()

    Bob.pickX()
    Yb = Bob.getY()

    Alice.calcS(Bob.Y)
    Bob.calcS(Alice.Y)
    print("Alice and Bob's secret keys before public keys being tampered: ", Alice.s, Bob.s)

    Alice.Y = Alice.q # Ya -> q
    Bob.Y = Bob.q # Yb -> q

    # Cause Alice and Bob's secret keys to be always 0
    Alice.calcS(Bob.Y)
    Bob.calcS(Alice.Y)
    print("Alice and Bob's secret keys after public keys being tampered: ", Alice.s, Bob.s)

    # Ka = Kb
    Ka = hashlib.sha256(str(Alice.s).encode('utf-8')).digest()[:16]
    Kb = hashlib.sha256(str(Bob.s).encode('utf-8')).digest()[:16]

    Ma = "Hi Bob!"
    Mb = "Hi Alice!"

    iv = get_random_bytes(16)
    aCipher = CBC_encrypt(Ma, Kb, iv)
    bCipher = CBC_encrypt(Mb, Ka, iv)

    newMa = CBC_decrypt(aCipher, Ka, iv)
    newMb = CBC_decrypt(bCipher, Kb, iv)
    
    print("Alice's message to Bob: ", newMa.decode('utf-8'))
    print("Bob's message to Alice: ", newMb.decode('utf-8'))
    print()

    # task 2-2
    print("*** Task 2-2 ***")
    Alice = Person()
    Bob = Person()

    # Cause Alice and Bob's secret keys to be always 1
    Alice.a = 1
    Bob.a = 1

    Alice.pickX()
    Ya = Alice.getY()

    Bob.pickX()
    Yb = Bob.getY()

    Alice.calcS(Bob.Y)
    Bob.calcS(Alice.Y)
    print("Alice and Bob's secret keys after 'generator a' being tampered: ", Alice.s, Bob.s)

    Ma = "Hi Bob!"
    Mb = "Hi Alice!"

    iv = get_random_bytes(16)
    aCipher = CBC_encrypt(Ma, Kb, iv)
    bCipher = CBC_encrypt(Mb, Ka, iv)

    newMa = CBC_decrypt(aCipher, Ka, iv)
    newMb = CBC_decrypt(bCipher, Kb, iv)
    
    print("Alice's message to Bob: ", newMa.decode('utf-8'))
    print("Bob's message to Alice: ", newMb.decode('utf-8'))
    print()
    

if __name__ == "__main__":
    main()
