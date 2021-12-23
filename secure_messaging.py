import cryptography
from cryptography.fernet import Fernet


def symmetric_key():
    return Fernet.generate_key()


key = symmetric_key()

data = "would this work?"

fern = Fernet(key)
encr = fern.encrypt(data.encode())
decr = fern.decrypt(encr)
print(decr.decode())
