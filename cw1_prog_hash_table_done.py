import hashlib
import string
import random
import pprint
from prettytable import PrettyTable


class HashTable:
    def __init__(self, capacity):
        self.capacity = capacity
        self.buckets = [None] * capacity

    def hash(self, key):
        return sum(ord(c) for c in key) % self.capacity

    def set(self, key, value):
        hashed_key = self.hash(key)
        if self.buckets[hashed_key] is None:
            self.buckets[hashed_key] = []
        self.buckets[hashed_key].append((key, value))

    def get(self, key):
        hashed_key = self.hash(key)
        if self.buckets[hashed_key] is not None:
            for k, v in self.buckets[hashed_key]:
                if k == key:
                    return v
        return None


def generate_passwords():
    length = 6
    num_passwords = 100

    chars = string.ascii_letters + string.digits + string.punctuation
    passwords = HashTable(num_passwords)
    count = 0
    while count < num_passwords:
        password = ''.join(random.choices(chars, k=length))
        hashed_password = hashing(password)
        reduced_hash = reduction(hashed_password)
        passwords.set(reduced_hash, password)
        count += 1
    # Get a list of all the reduced hashes in the hash table
    reduced_hashes = []
    for bucket in passwords.buckets:
        if bucket is not None:
            for reduced_hash, password in bucket:
                reduced_hashes.append(reduced_hash)
    # Sort the reduced hashes in alphabetical order
    reduced_hashes.sort()
    # Create a new hash table with the sorted reduced hashes and their corresponding passwords
    sorted_passwords = HashTable(num_passwords)
    for reduced_hash in reduced_hashes:
        password = passwords.get(reduced_hash)
        sorted_passwords.set(reduced_hash, password)
    return sorted_passwords


def hashing(password):
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    return hashed_password


def reduction(hashed_password, output_length=8):
    hashed_password_bytes = bytes.fromhex(hashed_password)
    least_significant_bytes = hashed_password_bytes[-8:]
    integer_value = int.from_bytes(least_significant_bytes, byteorder='big')
    output = hex(integer_value)[2:]
    if len(output) > output_length:
        output = output[:output_length]
    return output


def chain_len(input_string, num_repetitions):
    if num_repetitions == 0:
        return input_string
    else:
        reduced_hash = reduction(input_string)
        return chain_len(reduced_hash, num_repetitions-1)


def reduce_hash(hash):
    reduced_hash = reduction(hash)
    return reduced_hash


password_dict = generate_passwords()

# Create a table to display the passwords
table = PrettyTable()
table.field_names = ["Password", "Reduced Hash", "Hashed Password"]
for bucket in password_dict.buckets:
    if bucket is not None:
        for reduced_hash, password in bucket:
            hashed_password = hashing(password)
            table.add_row([password, reduced_hash, hashed_password])

print(table)

# Save passwords to file
with open("data.txt", "w") as file:
    for bucket in password_dict.buckets:
        if bucket is not None:
            for reduced_hash, password in bucket:
                hashed_password = hashing(password)
                file.write(f"{password} : {reduced_hash} : {hashed_password}\n".replace("'", ""))






# Compare input hash to saved hashes
hash_input = input("Enter the hash: ")
reduced_hash = chain_len(hash_input, 10)
print("The reduced hash is:", reduced_hash)


def compare_hash_to_dict(hash_input, password_dict):
    # Reduce the hash input
    reduced_hash = chain_len(hash_input, 10)
    # Check if the reduced hash matches any of the reduced hashes in the hash table
    if password_dict.get(reduced_hash) is not None:
        # If a match is found, print the corresponding password
        print(f"Match found: Password for hash: {password_dict.get(reduced_hash)}")
    else:
        print(f"No match found for hash {hash_input}")


compare_hash_to_dict(hash_input, password_dict)

