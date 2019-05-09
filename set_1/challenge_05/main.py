import base64
import binascii

def score_english(text):
    occurence_table = {
            'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
            'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06094, 'j': 0.00153,
            'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
            'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
            'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
            'z': 0.00074, ' ': 0.18394
            }
    return sum([occurence_table.get(chr(byte), -0.00010) for byte in text.lower()])

def repeating_key_xor(plaintext, key):
    temp = bytearray(plaintext)
    for i in range(len(plaintext)):
        temp[i] ^= key[i % len(key)]
    return temp

plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = b"ICE"

EXPECTED = b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

ciphertext = binascii.hexlify(repeating_key_xor(plaintext, key))
print(ciphertext)

if (ciphertext == EXPECTED):
    print("Successful")
else:
    print("Incorrectly encrypted, expecting\n{}".format(EXPECTED))

