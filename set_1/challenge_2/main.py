input_1 = bytes.fromhex("1c0111001f010100061a024b53535009181c")
input_2 = bytes.fromhex("686974207468652062756c6c277320657965")
EXPECTED = bytearray.fromhex("746865206b696420646f6e277420706c6179")

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

result = fixed_xor(input_1, input_2)
print(result)
if (result == EXPECTED):
    print("Successful")
else:
    print("Incorrect, expecting\n{}".format(EXPECTED))
