__author__ = 'onyekaigabari'

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
import os

def generateDHContribution(g, p):
    """
    Generate Diffie Hellman contribution
    :param g: generator
    :param p: safe prime
    :return: contribution
    """
    a = os.urandom(16)
    return pow(g,a,p)

def getServerPublicKey(filePath):
    """
    Get server public key file
    :param filePath: path to file
    :return: public key
    """
    try:
        with open(filePath, 'rb') as keyFile:
            publicKey = serialization.load_pem_public_key(
                keyFile.read(),
                password=None,
                backend=default_backend()
            )
        return publicKey
    except IOError as e :
        print " couldn't read ", filePath, " : ", e
        return -1

def generateSaltedPasswordHash(hKey, salt, password):
    """
    Generate salted password hash using HMAC
    :param hKey: hmac key
    :param salt: salt
    :param password
    :return: cipher text
    """
    h = hmac.HMAC(hKey, hashes.SHA256(), backend=default_backend())
    h.update(salt+password)
    pwdHash = h.finalize()
    print " password Hash: ", pwdHash
    return pwdHash

def generatePublicPrivateKeys():
    """
    Generate private and public keys
    :return: pem, pem_public
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    public_key = private_key.public_key()
    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    pem_public = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Just writing them into files for now, we can decide where and how to store them, maybe just use variables?
    with open("client_private_key.txt", "w") as f:
        f.write(str(pem))

    with open("client_public_key.txt", "w") as f:
        f.write(str(pem_public))

    # Making the function also return them in case we want to store in variables.
    return pem, pem_public

def encryptUsingPublicKey(key, data):
    """
    Encrypt message using asymmetric key
    :param key: asymmetric public key
    :param data: data to encrypt
    :return: cipher text
    """
    print "Use private key to encrypt the data"
    cipher_text = key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return cipher_text

def encyptUsingSymmetricKey(key, data):
    """
    Encrypt message using symmetric key
    :param key: symmetric key
    :param data: data to encrypt
    :return: cipher text
    """
    print "Use shared key to encrypt data"
    backend = default_backend()
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return ct

def decryptUsingPrivateKey(key, cipher):
    """
    Decrypt message using private key
    :param key:
    :param cipher:
    :return:
    """
    print "Decrypt the data using private key"
    data = key.decrypt(
        cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return data

def decryptUsingSymetricKey(key):
    print "Decrypt using the shared key"