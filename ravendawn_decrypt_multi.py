from FileDecryptor import FileDecryptor
import argparse
import os

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='FileDecryptor: Decrypt and process files.')
    parser.add_argument('-d', '--data', help='Path to the data.bin file', default=None)
    parser.add_argument('-o', '--output', help='Output directory for the extracted files', default='.\\output')
    args = parser.parse_args()

    output_directory = args.output if args.output else os.path.join(os.getcwd(), 'output')
    print(f"Outputting to the following directory: {output_directory}")
    decryptor = FileDecryptor(output_directory)
    data_bin_path = args.data if args.data else decryptor.find_data_bin()
    decryptor.extract_data_bin(data_bin_path)
    choice = input("The files have been extracted do you want to continue with decryption? [Y/N]: ")
    if choice.lower() == 'y':    
        decrypted_files, failed_decryption_files = decryptor.decrypt_all_files()
        if failed_decryption_files:
            print("Some files could not be decrypted:")
            for file in failed_decryption_files:
                print(file)
        else:
            choice = input("Do you want to start decompiling the lua files? [Y/N]: ") or "Y"
            if choice.lower() == 'y':
                overwrite_choice = input("Do you want to overwrite existing files with the decompiled files? [Y/N]: ") or "Y"
                backup_choice = False
                file_extension = ".decompiled"  # Default extension
                if overwrite_choice.lower() == 'y':
                    backup_choice = input("Do you want to back up the original files as .backup? [Y/N]: ") or "Y"
                    backup_choice = backup_choice.lower() == 'y'
                else:
                    file_extension = input("Provide a file extension to append (default is .decompiled): ") or ".decompiled"
                decryptor.decompile_all_lua_files(decrypted_files, overwrite=overwrite_choice.lower() == 'y', backup=backup_choice, extension=file_extension)
            else:
                print("Decompiler not decompiling. Exiting program")
                exit(1)
            
        print("All files processed successfully.")
    else:
        print("Aborting decryption, leaving extracted files in place.")
        exit(1)