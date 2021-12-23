import rsa

def asymmetric_keys():
    #generates public and corresponding private key
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

# pub, priv = asymmetric_keys()
#
# message = "This is a message"
#
# egassem = encrypt(message, pub)
# re_message = decrypt(egassem, priv)
#
# print(re_message == message)
