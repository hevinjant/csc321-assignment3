import hashlib
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def gcd(x, y):
    if x == 0:
        return y
    return gcd(y % x, x)

class RSA:
    def __init__(self, p, q):
        self.p = p
        self.q = q
        self.e = 65537
        #self.e = 7
        self.publicKey, self.privateKey = self.getKeys()
    
    def getKeys(self):
        n = self.p * self.q
        phi = (self.p - 1) * (self.q - 1)
        d = pow(self.e, -1, phi) # inverse mod
        publicKey = (self.e, n)
        privateKey = (d, n)
        return publicKey, privateKey

    def encrypt(self, plaintext):
        e, n = self.publicKey
        if plaintext > n:
            print("error encrypt(): plaintext is longer than n.")
            return
        ciphertext = pow(plaintext, e, n)
        return ciphertext

    def decrypt(self, ciphertext):
        d, n = self.privateKey
        plaintext = pow(ciphertext, d, n)
        return plaintext

def CBC_encrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def CBC_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def malloryF(malloryValue, aliceRSA):
    newCiphertext = aliceRSA.encrypt(malloryValue)
    return newCiphertext

def main():
    # RSA Demo
    print("*** RSA DEMO ***")
    AliceRSA = RSA(17, 11)
    alicePlaintext = 11
    cipher = AliceRSA.encrypt(alicePlaintext)
    print("Alice ciphertext: ", cipher)
    alicePlaintext_2 = AliceRSA.decrypt(cipher)
    print("Alice Plaintext: ", alicePlaintext_2)
    print()

    # MITM
    print("*** MITM DEMO ***")
    AliceRSA = RSA(17, 11) 
    alice_e, alice_n = AliceRSA.publicKey # Alice sends public keys
    bobSymmetricKey = 99 # Bob's symmetric key
    bobCiphertext = AliceRSA.encrypt(bobSymmetricKey) # Bob encrypts his symmetric key using Alice's public key
    print("Bob's symmetric key: ", bobSymmetricKey)
    print("Bob's ciphertext: ", bobCiphertext)

    MalloryRSA = RSA(29, 23)
    malloryFakeKey = 99
    bobCiphertext = malloryF(malloryFakeKey, AliceRSA) # Mallory tampers Bob's ciphertext, Mallory provides fake key to be encrypted using Alice's public key
    bobSymmetricKey = AliceRSA.decrypt(bobCiphertext) # Alice decrypts Bob's symmetric key (which is Mallory's fake key) using her private key
    print("Bob's new symmetric key: ", bobSymmetricKey)

    # Now Mallory knows that she can decrypts Alice's secret message with fake Bob's symmetric key

    hashedBobSymmetricKey = hashlib.sha256(str(bobSymmetricKey).encode('utf-8')).digest() # Bob's symmetric key (which is Mallory's fake key) is hashed
    iv = get_random_bytes(16)
    aliceSecretMessage = b"Hi Bob!"
    print("Alice's secret message to Bob: ", aliceSecretMessage)
    ciphertext_CBC = CBC_encrypt(aliceSecretMessage, hashedBobSymmetricKey, iv) # Alice encrypts her secret message using AES-CBC
    print("Alice's secret ciphertext: ", ciphertext_CBC)

    hashedMalloryFakeKey = hashlib.sha256(str(malloryFakeKey).encode('utf-8')).digest()
    plaintext_CBC = CBC_decrypt(ciphertext_CBC, hashedMalloryFakeKey, iv) # Mallory decrypts Alice's secret message using AES-CBC
    print("Mallory reads Alice's secret message: ", plaintext_CBC)

if __name__ == "__main__":
    main()