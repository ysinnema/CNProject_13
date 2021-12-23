import rsa


#generate public and corresponding private key
def asymmetric_keys():
    return rsa.newkeys(1024)


def get_public_key(n, e):
    return rsa.PublicKey(n, e)


def encrypt(content, key):
    return rsa.encrypt(content.encode('utf-8'), key)


def decrypt(cipher_content, key):
    try:
        return rsa.decrypt(cipher_content, key).decode('ascii')
    except:
        return False
