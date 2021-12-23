import cryptography
from cryptography.fernet import Fernet


def symmetric_key():
    return Fernet.generate_key()


def encrypt(content, key):
    fern = Fernet(key)
    return fern.encrypt(content.encode('utf-8'))


def decrypt(cipher_content, key):
    fern = Fernet(key)
    return fern.decrypt(cipher_content).decode('ascii')

