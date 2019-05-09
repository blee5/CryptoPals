def detect_ECB(ciphertext):
    """
    Returns if there are any repeated blocks found in the ciphertext,
    if yes, it was probably encrypted in ECB mode.
    """
    ciphertext = bytes(ciphertext)
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    found_blocks = set()
    for block in blocks:
        if block in found_blocks:
            return True
        found_blocks.add(block)
    return False
    
def main():
    with open("input.txt", 'r') as f:
        lines = f.read().split()
    lines = [bytearray.fromhex(line) for line in lines]
    for line in lines:
        if detect_ECB(line):
            print(line)


if __name__ == "__main__":
    main()
