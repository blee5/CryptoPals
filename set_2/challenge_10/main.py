import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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

def AES_128_CBC_encrypt(plaintext, key, IV):
    ciphertext = bytearray(len(plaintext))
    prev_block = IV
    for i in range(0, len(plaintext), 16):
        ciphertext[i: i + 16] = AES_128_ECB_encrypt(
                fixed_xor(plaintext[i: i + 16], prev_block),
                key)
        prev_block = ciphertext[i: i + 16]
    return ciphertext

def AES_128_CBC_decrypt(ciphertext, key, IV):
    plaintext = bytearray(len(ciphertext))
    prev_block = IV
    for i in range(0, len(ciphertext), 16):
        plaintext[i: i + 16] = fixed_xor(
                AES_128_ECB_decrypt(ciphertext[i: i + 16], key),
                prev_block)
        prev_block = ciphertext[i: i + 16]
    return plaintext

def pad_pkcs7(data, block_size):
    """
    Pads data into a multiple of block_size.
    """
    pad_length = (block_size - len(data)) % block_size
    if pad_length == 0:
        pad_length = block_size

    padding = bytes([pad_length for i in range(pad_length)])
    return data + padding

def fixed_xor(a, b):
    '''
    Given two arrays a and b with equal length,
    XOR them together and return it.
    '''
    assert len(a) == len(b), "Length of two buffers must be equal"
    c = bytearray(a)
    for i in range(len(a)):
        c[i] ^= b[i]
    return c


def main():
    with open("input.txt", 'r') as f:
        ciphertext = base64.b64decode(f.read().replace('\n', ''))

    IV = bytes(16)
    KEY = b"YELLOW SUBMARINE"

    assert AES_128_ECB_decrypt(AES_128_ECB_encrypt(ciphertext, KEY), KEY) == ciphertext
    print(AES_128_CBC_decrypt(ciphertext, KEY, IV).decode('ascii'))

if __name__ == "__main__":
    main()
