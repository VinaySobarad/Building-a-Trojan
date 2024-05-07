import sys

ENCRYPTION_KEY = "h4cks3nb3rg"

def xor(input_data, encryption_key):
    encryption_key = str(encryption_key)
    l = len(encryption_key)
    output_bytes = bytearray()

    for i in range(len(input_data)):
        current_data_element = input_data[i]
        current_key = encryption_key[i % len(encryption_key)]
        output_bytes.append(current_data_element ^ ord(current_key))

    return output_bytes

try:
    input_file_path = sys.argv[1]
except IndexError:
    print("Usage: C:\Python27\python.exe encrypt_with_xor.py PAYLOAD_FILE > OUTPUT_FILE")
    sys.exit()

with open(input_file_path, "rb") as file:
    plaintext = file.read()

ciphertext = xor(plaintext, ENCRYPTION_KEY)

try:
    output_file_path = input_file_path.replace(".bin", "_encrypted.bin")
    with open(output_file_path, "wb") as file:
        file.write(ciphertext)
    print(f"Output written to {output_file_path}")
except Exception as e:
    print("An error occurred while writing the output file:", e)
