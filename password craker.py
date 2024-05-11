import hashlib

def load_hashes(hash_file):
    with open(hash_file, 'r') as file:
        return [line.strip() for line in file]  #lstrip() && rstrip()

def load_dictionary(dict_file):
    with open(dict_file, 'r') as file:
        return [line.strip() for line in file]  #lstrip && rstrip

def crack_passwords(hash_file, dict_file):
    hashes = load_hashes(hash_file)          #load file in to hashes
    passwords = load_dictionary(dict_file)   #load dict in to passwords
    
    cracked_passwords = {}                    #empty dictionary
    
    for password in passwords:
        for hash_str in hashes:
            if hashlib.md5(password.encode()).hexdigest() == hash_str: # encoding
                cracked_passwords[hash_str] = password
    
    return cracked_passwords


hash_file = input("enter the 'hashes.txt'     ")
dict_file = input("enter the 'dictionary.txt' ")
    
cracked_passwords = crack_passwords(hash_file, dict_file)
    
for hash_str, password in cracked_passwords.items():
    print(f"Cracked Password for Hash '{hash_str}': {password}")
