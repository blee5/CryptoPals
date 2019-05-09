import base64
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from random import randint

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
    return bytes(ciphertext)

def AES_128_CBC_decrypt(ciphertext, key, IV):
    plaintext = bytearray(len(ciphertext))
    prev_block = IV
    for i in range(0, len(ciphertext), 16):
        plaintext[i: i + 16] = fixed_xor(
                AES_128_ECB_decrypt(ciphertext[i: i + 16], key),
                prev_block)
        prev_block = ciphertext[i: i + 16]
    return bytes(plaintext)

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

def random_encryption(plaintext):
    key = os.urandom(16)
    IV = os.urandom(16)
    plaintext = os.urandom(randint(5, 10)) + plaintext + os.urandom(randint(5, 10))
    plaintext = pad_pkcs7(plaintext, 16)
    if randint(0, 1) == 0:
        ciphertext = AES_128_ECB_encrypt(plaintext, key)
        mode = "ECB"
    else:
        ciphertext = AES_128_CBC_encrypt(plaintext, key, IV)
        mode = "CBC"
    return (mode, ciphertext)

def main():
    plaintext = b"A" * 16 * 3
    success = 0
    trials = 10000
    for i in range(0, trials):
        test_data = random_encryption(plaintext)
        guess = "ECB" if detect_ECB(test_data[1]) else "CBC"
        answer = test_data[0]
        # print("Got {}, expecting {}".format(guess, answer))
        if guess == answer:
            success += 1
    print(success / trials * 100)
    

if __name__ == "__main__":
    main()
