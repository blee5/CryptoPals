import base64

ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

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

def single_key_xor(text, key):
    result = bytearray(text)
    return bytearray(map(lambda c: c ^ key, text))

candidates = []
for c in range(256):
    plaintext = single_key_xor(ciphertext, c)
    score = score_english(plaintext)
    candidates.append({"plaintext": plaintext, "score": score, "key": c})

print(sorted(candidates, key=lambda x: x["score"], reverse=True)[0])

