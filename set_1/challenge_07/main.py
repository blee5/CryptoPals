import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

KEY = b"YELLOW SUBMARINE"

def main():
    with open("input.txt", 'r') as f:
        encoded = f.read().replace('\n', '')
        ciphertext = base64.b64decode(encoded)

    AES_ECB = Cipher(algorithms.AES(KEY), modes.ECB(), backend=default_backend())
    decryptor = AES_ECB.decryptor()
    plaintext = decryptor.update(ciphertext)
    print(plaintext.decode('ascii'))

    decryptor.finalize()

if __name__ == "__main__":
    main()
