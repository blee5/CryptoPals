import base64

def score_english(text):
    occurence_table = {
            'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
            'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06094, 'j': 0.00153,
            'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
            'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
            'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
            'z': 0.00074, ' ': 0.18394,
            '.': 0.00100, '?': 0.00100, ',': 0.00100, '\'': 0.00100
            }
    return sum([occurence_table.get(chr(byte), -0.00200) for byte in text.lower()])

def repeating_key_xor(plaintext, key):
    temp = bytearray(plaintext)
    for i in range(len(plaintext)):
        temp[i] ^= key[i % len(key)]
    return temp

def single_key_xor(text, key):
    result = bytearray(text)
    return bytearray(map(lambda c: c ^ key, text))

def break_single_key_xor(ciphertext):
    candidates = []
    for c in range(256):
        plaintext = single_key_xor(ciphertext, c)
        score = score_english(plaintext)
        candidates.append({"plaintext": plaintext, "score": score, "key": c})
    return sorted(candidates, key=lambda x: x["score"], reverse=True)[0]

def hamming_distance(s1, s2):
    assert len(s1) == len(s2)
    distance = 0
    for c1, c2 in zip(s1, s2):
        diff = c1 ^ c2
        while diff:
            distance += diff & 1
            diff >>= 1
    return distance

def key_score(ciphertext, key_size):
    blocks = [ciphertext[i: i + key_size] for i in range(0, len(ciphertext), key_size)]
    scores = []
    i = 0
    for i in range(0, len(blocks) - 1):
        block_1 = blocks[i]
        block_2 = blocks[i+1]
        if len(block_1) != len(block_2):
            break
        scores.append(hamming_distance(block_1, block_2) / key_size)
    return sum(scores) / len(scores)

def main():
    # test hamming distance
    hamming_test = hamming_distance(b"this is a test", b"wokka wokka!!!")
    assert hamming_test == 37, hamming_test

    with open("input.txt", 'r') as f:
        encoded = f.read().replace('\n', '')
        ciphertext = base64.b64decode(encoded)

    hamming_distances = {key_size: key_score(ciphertext, key_size) for key_size in range(2, 41)}
    # Find the most likely key size based on the Hamming distances
    key_size = min(hamming_distances, key=lambda x:hamming_distances[x])

    # split the text into blocks
    blocks = [ciphertext[i: i + key_size] for i in range(0, len(ciphertext), key_size)]

    # transpose the blocks
    # we drop the last block because its length might not match the others
    # and this is easier than dealing with it
    blocks = [bytearray(i) for i in zip(*blocks[:-1])]
    key = bytearray()
    for block in blocks:
        key.append(break_single_key_xor(block)['key'])
    plaintext = repeating_key_xor(ciphertext, key)
    print("Key used: {}\n".format(key))
    print(plaintext.decode('ascii'))

if __name__ == '__main__':
    main()

