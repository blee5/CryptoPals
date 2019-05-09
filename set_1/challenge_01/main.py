import base64

input_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

EXPECTED = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

result = base64.b64encode(bytearray.fromhex(input_string)).decode('ascii')
print(result)

if (result == EXPECTED):
    print("Successful")
else:
    print("Incorrect, expecting\n{}".format(EXPECTED))

