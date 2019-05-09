def pad_pkcs7(data, block_size):
    """
    Pads data into a multiple of block_size.
    """
    pad_length = (block_size - len(data)) % block_size
    if pad_length == 0:
        pad_length = block_size

    padding = bytes([pad_length for i in range(pad_length)])
    return data + padding

def main():
    for i in range(0, 16):
        print(pad_pkcs7(b"YELLOW SUBMARINE", 16 + i))

if __name__ == "__main__":
    main()
