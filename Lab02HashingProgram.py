import os
import hashlib
import json

HASH_TABLE_FILE = "hash_table.json"

def hash_file(filepath):
    """Calculates SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except IOError:
        return None

def traverse_directory(directory):
    """Traverses a directory and hashes all files."""
    hash_table = {}

    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = hash_file(filepath)
            if file_hash:
                hash_table[filepath] = file_hash

    return hash_table

def generate_table():
    """Generates a hash table and stores it in a JSON file."""
    directory = input("Enter directory path to hash: ")

    if not os.path.isdir(directory):
        print("Invalid directory path.")
        return

    hash_table = traverse_directory(directory)

    with open(HASH_TABLE_FILE, "w") as f:
        json.dump(hash_table, f, indent=4)

    print("Hash table generated.")

def validate_hash():
    """Validates current files against stored hash table."""
    if not os.path.exists(HASH_TABLE_FILE):
        print("No hash table found. Generate one first.")
        return

    with open(HASH_TABLE_FILE, "r") as f:
        stored_hashes = json.load(f)

    directory = input("Enter directory path to verify: ")
    if not os.path.isdir(directory):
        print("Invalid directory path.")
        return

    current_hashes = traverse_directory(directory)

    # Check for modified or deleted files
    for filepath, stored_hash in stored_hashes.items():
        if filepath not in current_hashes:
            print(f"{filepath} has been deleted.")
        else:
            if current_hashes[filepath] == stored_hash:
                print(f"{filepath} hash is valid.")
            else:
                print(f"{filepath} hash is INVALID.")

    # Check for new files
    for filepath in current_hashes:
        if filepath not in stored_hashes:
            print(f"{filepath} is a new file.")

def main():
    """Main program logic."""
    print("1. Generate new hash table")
    print("2. Verify hashes")

    choice = input("Enter choice (1 or 2): ")

    if choice == "1":
        generate_table()
    elif choice == "2":
        validate_hash()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
