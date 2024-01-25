import os
import secrets
from aes import AES
from ctr import CTR
import getpass
import argparse
import hmac
import hashlib

# takes a stream of inputs and deals with it as blocks then appply what ever function (encrypt or decrypt) to each block
# then concatnates the result of each block to from  ghe output stream
def encrypt_decrypt(func, in_stream, block_size, count_start):
    return b"".join(
        [
            func(in_stream[i : i + block_size], i // block_size + count_start)
            for i in range(0, len(in_stream), block_size)
        ]
    )

# Initializes the block size to 16 bytes (standard AES block size).
# Generates a random 128-bit salt using secrets.
#
# Generates a random 10-byte nonce.
# Constructs the Initialization Vector (IV) by concatenating the nonce and a 6-byte counter initialized to 0
# Initializes an AES cipher with the provided password, salt, and key length.
# Initializes a CTR mode with the AES cipher and the nonce.
# Reads the input file into memory as a string.
# Converts the text to bytes using UTF-8 encoding.
# Calls the encrypt_decrypt function to encrypt the input file using the specified CTR mode.
# Concatenates the salt, IV, and the encrypted content into the file_out variable.
# Generates an HMAC (Hash-based Message Authentication Code) using the HMAC key derived from the AES key.
# The HMAC is computed over the entire ciphertext.
# Appends the HMAC to the ciphertext.
# Writes the final ciphertext (including salt, IV, and HMAC) to the output file in binary mode.
# Prints a success message with the output file path.
def encrypt_file(input_path, output_path, passwd):
    block_size = 16

    # Create a random 128-bit salt (16 bytes) used in the key derivation function
    salt = secrets.token_bytes(block_size)

    # Create a random 10-byte nonce
    nonce = secrets.token_bytes(10)

    # Create the IV from the nonce and the initial 6-byte counter value of 0
    counter = 0
    IV = nonce + counter.to_bytes(6, "big")

    # Start AES cipher
    cipher = AES(password_str=passwd, salt=salt, key_len=256)

    # Start CTR mode
    mode = CTR(cipher, nonce)

    # Read input file into memory
    with open(input_path, "r", encoding="utf-8") as f_in:
        file_in = f_in.read()

    # Convert text to bytes using UTF-8 encoding
    file_in_bytes = file_in.encode("utf-8")

    file_out = salt + IV + encrypt_decrypt(mode.encrypt, file_in_bytes, block_size, counter)

    # Create authentication HMAC and store it as the last two blocks of the file
    hmac_val = hmac.digest(key=cipher.hmac_key, msg=file_out, digest=hashlib.sha256)

    # Append HMAC to the ciphertext
    file_out += hmac_val

    # Write output file
    with open(output_path, "wb") as f_out:
        f_out.write(file_out)

    print(f"\nEncryption successfully completed! Ciphertext has been stored in: {output_path}")

# Initializes the block size to 16 bytes.
# Reads the encrypted input file into memory in binary mode.
# Extracts the salt, nonce, and initial counter value from the ciphertext.
# Extracts the HMAC value from the last 2 blocks of the ciphertext.
# Initializes an AES cipher with the provided password, salt, and key length.
# Compares the computed HMAC value with the extracted HMAC value to verify the integrity of the ciphertext.
# Initializes a CTR mode with the AES cipher and the nonce.
#
def decrypt_file(input_path, output_path, passwd):
    block_size = 16

    # Read input file into memory
    with open(input_path, "rb") as f_in:
        file_in = f_in.read()

    # Extract the salt from the first 128 bits (16 bytes) of the ciphertext
    salt = file_in[0:block_size]

    # Extract nonce from the first 10 bytes of the second block of the ciphertext
    nonce = file_in[block_size : block_size + 10]

    # Extract the starting counter value from the next 6 bytes of the ciphertext
    counter = file_in[block_size + 10 : block_size + 10 + 6]
    counter = int.from_bytes(counter, "big")

    # Extract the HMAC value from the last 2 blocks of the ciphertext
    hmac_val = file_in[-block_size:]

    # Start AES cipher
    cipher = AES(password_str=passwd, salt=salt, key_len=256)

    # Compare HMAC values (remove the HMAC value from the ciphertext before comparing)
    assert hmac.compare_digest(
        hmac_val,
        hmac.digest(
            key=cipher.hmac_key,
            msg=file_in[: -block_size],
            digest=hashlib.sha256,
        ),
    ), "HMAC check failed."

    # Start CTR mode
    mode = CTR(cipher, nonce)

    # Strip the salt, IV, and HMAC from the ciphertext
    file_in = file_in[2 * block_size : -block_size]

    file_out_bytes = encrypt_decrypt(mode.decrypt, file_in, block_size, counter)

    # Convert bytes to text using UTF-8 encoding
    file_out = file_out_bytes.decode("utf-8")

    # Write output file
    with open(output_path, "w", encoding="utf-8") as f_out:
        f_out.write(file_out)

    print(f"\nDecryption successfully completed! Plaintext has been stored in: {output_path}")

def main():
    print("Select operation:")
    print("1. Encrypt")
    print("2. Decrypt")

    operation = input("Enter operation number: ")

    if operation not in ['1', '2']:
        print("Invalid operation number.")
        return

    input_path = input("Enter input file path: ")
    output_path = input("Enter output file path: ")

    # Validate file paths
    if not os.path.isfile(input_path):
        print(f"Error: Input file does not exist at path: {input_path}")
        return

    # Ensure the output directory exists
    output_dir = os.path.dirname(output_path)
    if not os.path.exists(output_dir):
        print(f"Error: Output directory does not exist at path: {output_dir}")
        return

    if operation == '1':
        passwd = getpass.getpass("Enter secret message (password) for encryption: ")
        encrypt_file(input_path, output_path, passwd)
        print("Encrypting...")
    elif operation == '2':
        passwd = getpass.getpass("Enter secret message (password) for decryption: ")
        decrypt_file(input_path, output_path, passwd)
        print("Decrypting...")

if __name__ == "__main__":
    main()
