from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os


def encryptUsingPublicKey(key, data):
    print "Using public key to encrypt the data"
    cipher_text = key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return cipher_text


def encyptUsingSymetricKey(key, data):
    print "Using shared key to encrypt data"
    backend = default_backend()
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return ct


def createToken(client1, client2):
    print "Create token for the clients to talk to each other"


def decryptUsingPrivateKey(key, cipher):
    print "Decrypt the data using private key"
    data = key.decrypt(
        cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )


def decryptUsingSymetricKey(key, ct, iv):
    print "Decrypt using the shared key"
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(ct) + decryptor.finalize()
    return plain_text


# generates and returns the private and public keys.
def generatePublicPrivateKeys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    public_key = private_key.public_key()
    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    pem_public = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Just writing them into files for now, we can decide where and how to store them, maybe just use variables?
    with open("server_private_key.txt", "w") as f:
        f.write(str(pem))

    with open("server_public_key.txt", "w") as f:
        f.write(str(pem_public))

    # Making the function also return them in case we want to store in variables.
    return pem, pem_public

