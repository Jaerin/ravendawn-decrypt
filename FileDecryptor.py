from OpenSSL import crypto
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from base64 import b64decode
import lzma
import os
import zipfile
import argparse
import glob
import requests
import shutil
import subprocess

class FileDecryptor:
    def __init__(self, output_path):
        self.output_path = output_path
        self.decompiler_path = '.\\luajit-decompiler-v2.exe'
        self.decompiled_output_directory = '.\\decompiled'
        self.decompiler_present()

    def decompiler_present(self):
        if not os.path.isfile(self.decompiler_path):
            print(f"{self.decompiler_path} not found.")
            print(f"https://github.com/marsinator358/luajit-decompiler-v2/releases/download/Feb_25_2024/luajit-decompiler-v2.exe")
            choice = input("Do you want to download the decompiler? [Y/N]: ")
            if choice.lower() == 'y':
                print("Downloading...")
                url = 'https://github.com/marsinator358/luajit-decompiler-v2/releases/download/Feb_25_2024/luajit-decompiler-v2.exe'
                try:
                    response = requests.get(url)
                    response.raise_for_status()
                    with open(self.decompiler_path, 'wb') as f:
                        f.write(response.content)
                    print(f"Downloaded {self.decompiler_path}")
                except requests.exceptions.RequestException as e:
                    print(f"Failed to download {self.decompiler_path}: {e}")
                    exit(1)
            else:
                print("Decompiler is not present. Exiting.")
                exit(1)
                
    def find_data_bin(self):
        script_directory = os.getcwd()
        data_bin_path = os.path.join(script_directory, 'data.bin')
        if not os.path.isfile(data_bin_path):
            user_paths = glob.glob(r'C:\Users\*\AppData\Roaming\Ravendawn\ravendawn')
            for user_path in user_paths:
                possible_path = os.path.join(user_path, 'data.bin')
                if os.path.isfile(possible_path):
                    print(f"Found data.bin at {possible_path}")
                    choice = input("Do you want to use this file? [Y/N]: ")
                    if choice.lower() == 'y':
                        shutil.copy(possible_path, data_bin_path)
                        print(f"Copied data.bin to {script_directory}")
                        return data_bin_path
            print("data.bin not found in expected locations. Exiting.")
            exit(1)
        else:
            choice = input("Found data.bin in the script directory, do you want to use this file? [Y/N]: ")
            if choice.lower() == 'y':
                return data_bin_path
            else:
                user_paths = glob.glob(r'C:\Users\*\AppData\Roaming\Ravendawn\ravendawn')
                for user_path in user_paths:
                    possible_path = os.path.join(user_path, 'data.bin')
                    if os.path.isfile(possible_path):
                        print(f"Found data.bin at {possible_path}")
                        choice = input("Do you want to use this file? [Y/N]: ")
                        if choice.lower() == 'n':
                            print(f"No data.bin provided.  Provide the data.bin or use one found to continue.")
                            exit(1)    
                        choice = input("This may overwrite your existing data.bin in your script directory are you sure? [Y/N]: ")
                        if choice.lower() == 'y':
                            shutil.copy(possible_path, data_bin_path)
                            print(f"Copied data.bin to {script_directory}")
                            return data_bin_path
                print("data.bin not found in expected locations or protected. Exiting.")
                exit(1)

    def extract_data_bin(self, data_bin_path):
        if not os.path.exists(self.output_path):
            os.makedirs(self.output_path)
        
        with zipfile.ZipFile(data_bin_path, 'r') as zip_ref:
            print(f"Extracting {data_bin_path} to {self.output_path}...")
            zip_ref.extractall(self.output_path)
            print("Extraction complete.")


    def evp_decrypt(self, key, ciphertext, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext

    def get_bytes(self, num):
        x = num.to_bytes(0x10, 'big')
        if len(x) > 0:
            return x[-1]
        return 0

    def get_xor_file(self, filename):
        ret = []
        a = bytearray(filename, "ascii")
        for i in range(0, len(filename)):
            v28 = (bytes(filename[i], "ascii")[0] ^ len(filename)) + 0x69
            a[i] = v28
        return a

    def get_xor_key(self, file_data):
        return self.get_bytes(file_data[5] ^ 0x1337)

    def get_key(self, xored, xor_key):
        key = bytearray([0]*0x40)
        for i in range(0, 0x40, 8):
            curr = xored[(i + 105) % len(xored)]
            key[i] = self.get_bytes(curr)

            curr = (key[i] ^ xor_key) + 105
            key[i] = self.get_bytes(curr)   

            curr = xored[(i + 106) % len(xored)]
            key[i+1] = self.get_bytes(curr)

            curr = (key[i+1] ^ xor_key) + 105
            key[i+1] = self.get_bytes(curr)

            curr = xored[(i + 107) % len(xored)]
            key[i+2] = self.get_bytes(curr)

            curr = (key[i+2] ^ xor_key) + 105
            key[i+2] = self.get_bytes(curr)

            curr = xored[(i + 108) % len(xored)]
            key[i+3] = self.get_bytes(curr)

            curr = (key[i+3] ^ xor_key) + 105
            key[i+3] = self.get_bytes(curr)

            curr = xored[(i + 109) % len(xored)]
            key[i+4] = self.get_bytes(curr)

            curr = (key[i+4] ^ xor_key) + 105
            key[i+4] = self.get_bytes(curr)

            curr = xored[(i + 110) % len(xored)]
            key[i+5] = self.get_bytes(curr)

            curr = (key[i+5] ^ xor_key) + 105
            key[i+5] = self.get_bytes(curr)

            curr = xored[(i + 111) % len(xored)]
            key[i+6] = self.get_bytes(curr)

            curr = (key[i+6] ^ xor_key) + 105
            key[i+6] = self.get_bytes(curr)

            curr = xored[(i + 112) % len(xored)]
            key[i+7] = self.get_bytes(curr)

            curr = (key[i+7] ^ xor_key) + 105
            key[i+7] = self.get_bytes(curr)
        return bytes(key)

    def get_iv(self, filename, xor_key):
        iv = bytearray([0]*0x10)
        for j in range(0, 0x10, 8):
            v68 = 0
            if (j & 1) == 0:
                v68 = xor_key
            v69 = 0
            if ( j == 3 * (j // 3) ):
                v69 = 105
            iv[j] = self.get_bytes(v68 + v69)

            v71 = len(filename) + (iv[j]^xor_key)

            iv[j] = self.get_bytes(v71)

            v74 = j - 1
            v75 = 0

            if ( (j - 1) & 1) == 0:
                v75 = xor_key
            v76 = 0

            if j - 3 * ((v74 + 2) // 3) == -1:
                v76 = 105
            iv[j + 1] = self.get_bytes(v75 + v76)

            v78 = len(filename) + (iv[j+1]^xor_key)
            iv[j+1] = self.get_bytes(v78)

            v81 = 0

            if ( j - 3 * ((v74 + 3) // 3) == -2):
                v81 = 105
            iv[j+2] = self.get_bytes(v68 + v81)

            v83 = len(filename) + (iv[j+2]^xor_key)
            iv[j+2] = self.get_bytes(v83)

            v86 = 0
            if ( not(j + 2 * (1 - (v74 + 4) // 3) + 1 - (v74 + 4) // 3) ):
                v86 = 105
            iv[j + 3] = self.get_bytes(v75 + v86)

            v88 = len(filename) + (iv[j+3]^xor_key)
            iv[j+3] = self.get_bytes(v88)

            v91 = 0
            if ( j - 3 * ((v74 + 5) // 3) == -4):
                v91 = 105
            iv[j + 4] = self.get_bytes(v68 + v91)

            v93 = len(filename) + (iv[j+4]^xor_key)
            iv[j+4] = self.get_bytes(v93)

            v96 = 0
            if ( j - 3 * ((v74 + 6) // 3) == -5 ):
                v96 = 105
            iv[j+5] = self.get_bytes(v75 + v96)

            v98 = len(filename) + (iv[j+5]^xor_key)
            iv[j + 5] = self.get_bytes(v98)

            v101 = 0

            if ( not(-3 * ((v74 + 7) // 3) + j + 6) ):
                v101 = 105

            iv[j + 6] = self.get_bytes(v68 + v101)

            v103 = len(filename) + (iv[j+6]^xor_key)
            iv[j+6] = self.get_bytes(v103)

            v106 = 0
            if ( j - 3 * ((v74 + 8) // 3) == -7 ):
                v106 = 105
            iv[j + 7] = self.get_bytes(v75 + v106)

            v108 = len(filename) + (iv[j+7]^xor_key)
            iv[j+7] = self.get_bytes(v108)

        return iv

    def decrypt_file(self, file_path):
        file_name = os.path.basename(file_path)

        try:
            with open(file_path, 'rb') as encrypted_file:
                if encrypted_file.read(4) != b'P00P':
                    print(f"File format not recognized, skipping: {file_path}")
                    return
                encrypted_file.seek(0)
                xor_key2 = self.get_xor_key(bytearray(encrypted_file.read()))
                key = self.get_key(self.get_xor_file(file_name), xor_key2)
                iv = self.get_iv(file_name, xor_key2)

            with open(file_path, 'rb') as file:
                file.read(16)
                encrypted_content = file.read()
                decrypted = self.evp_decrypt(key[:32], encrypted_content, iv)
                decompressed = lzma.decompress(decrypted)

            with open(file_path, 'wb') as new_file:
                new_file.write(decompressed)

        except Exception as e:
            print(f"Failed to decrypt {file_path}: {e}")

    def decrypt_all_files(self):
        decrypted_files = []
        failed_files = []
        for root, _, files in os.walk(self.output_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                try:
                    print(f"Decrypting... {file_path}")
                    self.decrypt_file(file_path)
                    decrypted_files.append(file_path)
                except Exception as e:
                    print(f"Failed to decrypt {file_path}: {e}")
                    failed_files.append(file_path)
        return decrypted_files, failed_files

    def is_luajit_file(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                # Read only the first 4 bytes for the signature
                signature = file.read(4)
            # Compare the read signature to the expected LuaJIT signature
            return signature == b'\x1B\x4C\x4A\x02'
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return False

    def decompile_lua_file(self, file_path, temp_decompiled_dir, overwrite=False, backup=False, extension=".decompiled"):
        temp_decompiled_file = os.path.join(temp_decompiled_dir, os.path.basename(file_path))
        cmd = [self.decompiler_path, file_path, '-o', temp_decompiled_dir]
        result = subprocess.run(cmd, check=False)
        if result.returncode != 0:
            print(f"Decompiler failed with return code {result.returncode}. Exiting.")
            exit(1)

        if not os.path.exists(temp_decompiled_file):
            print(f"Expected decompiled file not found: {temp_decompiled_file}")
            return

        final_decompiled_file_path = file_path if overwrite else file_path + extension

        if overwrite and os.path.exists(final_decompiled_file_path):
            if backup:
                backup_file_path = file_path + ".backup"
                os.rename(final_decompiled_file_path, backup_file_path)
                print(f"Backed up existing decompiled file: {backup_file_path}")
            shutil.move(temp_decompiled_file, final_decompiled_file_path)
            print(f"Moved decompiled file from {temp_decompiled_file} to {final_decompiled_file_path}")
        elif not os.path.exists(final_decompiled_file_path):
            shutil.move(temp_decompiled_file, final_decompiled_file_path)
            print(f"Moved decompiled file from {temp_decompiled_file} to {final_decompiled_file_path}")
        else:
            print(f"File already exists and overwrite is not allowed: {final_decompiled_file_path}")

    def decompile_all_lua_files(self, files, overwrite=False, backup=False, extension=".decompiled"):
        temp_decompiled_dir = os.path.join(self.output_path, 'temp_decompiled')
        os.makedirs(temp_decompiled_dir, exist_ok=True)

        for file_path in files:
            if not file_path.lower().endswith('.lua'):
                continue
            if self.is_luajit_file(file_path):
                self.decompile_lua_file(file_path, temp_decompiled_dir, overwrite, backup, extension)
            else:
                print(f"Skipped non-LuaJIT file: {file_path}")
        shutil.rmtree(temp_decompiled_dir)



    def cleanup_temporary_files(self):
        temp_decompiled_dir = os.path.join(self.output_path, 'temp_decompiled')
        if os.path.exists(temp_decompiled_dir):
            shutil.rmtree(temp_decompiled_dir)
            print(f"Cleaned up temporary directory: {temp_decompiled_dir}")



