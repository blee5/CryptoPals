import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

KEY = os.urandom(16)

def AES_128_ECB_encrypt(plaintext, key):
    AES_128_ECB = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = AES_128_ECB.encryptor()
    ciphertext = encryptor.update(bytes(plaintext))
    encryptor.finalize()
    return ciphertext

def AES_128_ECB_decrypt(ciphertext, key):
    AES_128_ECB = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = AES_128_ECB.decryptor()
    plaintext = decryptor.update(bytes(ciphertext))
    decryptor.finalize()
    return plaintext

def pad_pkcs7(data, block_size):
    pad_length = (block_size - len(data)) % block_size
    if pad_length == 0:
        pad_length = block_size

    padding = bytes([pad_length for i in range(pad_length)])
    return data + padding

def unpad_pkcs7(data):
    pad_byte = data[-1]
    if data.endswith(bytes([pad_byte] * pad_byte)):
        return data[:-pad_byte]
    raise Exception("Invalid PKCS#7 padding", data)

def kv_parse(kv):
    pairs = [pair.split('=') for pair in kv.split('&') if pair]
    return {pair[0]: pair[1] for pair in pairs}

def profile_for(email):
    email = email.replace('=', '')
    email = email.replace('&', '')
    encoded = "email={}&uid=13&role=user".format(email)
    return encrypt_profile(encoded)

def encrypt_profile(profile):
    padded = pad_pkcs7(bytes(profile, 'ascii'), 16)
    return AES_128_ECB_encrypt(padded, KEY)

def decrypt_profile(ciphertext):
    profile = unpad_pkcs7(AES_128_ECB_decrypt(ciphertext, KEY)).decode('ascii')
    return kv_parse(profile)

def main():
    base_length = len(profile_for(""))
    # cut out a block that looks like "`admin` || padding" when decrypted
    prepad_length = 16 - len("email=")
    admin_suffix = profile_for("A" * prepad_length + "admin" + chr(11) * 11)[16:32]
    # cut out blocks that looks like "stuff || `&role=`" when decrypted
    prepad_length = 32 - len("email=&uid=13&role=")
    prefix = profile_for("A" * prepad_length)[:32]
    
    # join the snippets to create "stuff || `&role=admin` || padding"
    print(decrypt_profile(prefix + admin_suffix))

if __name__ == "__main__":
    main()
