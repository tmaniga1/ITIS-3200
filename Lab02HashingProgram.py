import hashlib
import os
import json

HASH_FILE = "hash_table.json"

def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None

def generate_hash_table():
    target_dir = input("Enter the directory path to hash: ").strip()
    
    if not os.path.exists(target_dir):
        print("Error: Directory not found.")
        return

    hash_dict = {}
    print(f"Scanning directory: {target_dir}...")
    
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            if file == HASH_FILE: 
                continue
            full_path = os.path.join(root, file)
            file_hash = calculate_sha256(full_path)            
            abs_path = os.path.abspath(full_path)
            hash_dict[abs_path] = file_hash

    with open(HASH_FILE, 'w') as json_file:
        json.dump(hash_dict, json_file, indent=4)
        
    print(f"Hash table generated successfully! Saved to '{HASH_FILE}'.")
def verify_hashes():
    if not os.path.exists(HASH_FILE):
        print(f"Error: '{HASH_FILE}' not found. Please generate a table first.")
        return
    with open(HASH_FILE, 'r') as json_file:
        stored_hashes = json.load(json_file)

    print("\nVerifying hashes...")
    current_files_found = set()
    if not stored_hashes:
        print("Hash table is empty.")
        return
    sample_path = list(stored_hashes.keys())[0]
    root_dir = os.path.dirname(sample_path) 
    hash_to_old_path = {v: k for k, v in stored_hashes.items()}
    missing_files = []
    for file_path, stored_hash in stored_hashes.items():
        if os.path.exists(file_path):
            current_hash = calculate_sha256(file_path)
            current_files_found.add(os.path.abspath(file_path))
            
            if current_hash == stored_hash:
                print(f"[VALID] {file_path}")
            else:
                print(f"[INVALID] {file_path} (Hash mismatch!)")
        else:
            missing_files.append((file_path, stored_hash))
    common_path = os.path.commonpath(list(stored_hashes.keys()))
    
    for root, dirs, files in os.walk(common_path):
        for file in files:
            if file == HASH_FILE: continue
            
            full_path = os.path.abspath(os.path.join(root, file))
            
            if full_path not in stored_hashes:
                current_hash = calculate_sha256(full_path)
                rename_detected = False
                for missing_path, missing_hash in missing_files:
                    if current_hash == missing_hash:
                        print(f"[RENAME DETECTED] '{os.path.basename(missing_path)}' "
                              f"renamed to '{os.path.basename(full_path)}'")
                        missing_files.remove((missing_path, missing_hash))
                        rename_detected = True
                        break
                
                if not rename_detected:
                    print(f"[NEW FILE] {full_path}")
    for missing_path, _ in missing_files:
        print(f"[DELETED] {missing_path}")

def main():
    while True:
        print("\n Lab 02 Hashing Program")
        print("1. Generate new hash table")
        print("2. Verify hashes")
        print("3. Exit")
        
        choice = input("Select an option: ")
        
        if choice == '1':
            generate_hash_table()
        elif choice == '2':
            verify_hashes()
        elif choice == '3':
            print("Exiting.")
            break
        else:
            print("Invalid selection.")

if __name__ == "__main__":
    main()
