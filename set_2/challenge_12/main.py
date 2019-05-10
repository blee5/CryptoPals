import base64
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from random import randint

KEY = os.urandom(16)
MYSTERY_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

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

def detect_ECB(ciphertext):
    """
    Returns if there are any repeated blocks found in the ciphertext,
    if yes, it was probably encrypted in ECB mode.

    Of course, if there was no repeating blocks in the plaintext,
    this function would not work at all.
    """
    ciphertext = bytes(ciphertext)
    for offset in range(0, 1):
        blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        found_blocks = set()
        for block in blocks:
            if block in found_blocks:
                return True
            found_blocks.add(block)
    return False

def oracle(plaintext):
    IV = os.urandom(16)
    padded = pad_pkcs7(plaintext + base64.b64decode(MYSTERY_STRING), 16)
    #  padded = pad_pkcs7(plaintext + b"YELLOW SUBMARINEYELLOW SUBMARIN", 16)
    ciphertext = AES_128_ECB_encrypt(padded, KEY)
    return ciphertext

def main():
    ct_length = len(oracle(b""))

    # determine blocksize of the cipher
    prepad = b"A"
    while True:
        new_length = len(oracle(prepad))
        if ct_length != new_length:
            block_size = new_length - ct_length
            break
        prepad += b"A"
    assert block_size == 16, block_size

    # check if ECB
    prepad = b"A" * block_size * 2
    assert detect_ECB(oracle(prepad))

    num_blocks = ct_length // block_size
    offset = (num_blocks - 1) * block_size
    prepad_length = offset + block_size - 1

    plaintext = bytearray()
    for i in range(ct_length):
        blocks_dict = {}
        prepad = bytearray(b"*" * prepad_length + plaintext)
        for c in range(256):
            prepad.append(c)
            ct_block = oracle(prepad)[offset: offset+block_size]
            blocks_dict[ct_block] = c
            prepad = prepad[:-1]

        prepad = b"*" * prepad_length
        ct_block = oracle(prepad)[offset: offset+block_size]

        try:
            plaintext.append(blocks_dict[ct_block])
        except:
            # hopefully the padding part
            plaintext = plaintext[:-1]
            pad_length = ct_length - len(plaintext)
            plaintext += bytes([pad_length] * pad_length)
            break

        prepad_length -= 1
    print(plaintext)

if __name__ == "__main__":
    main()
