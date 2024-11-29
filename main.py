import os
from Crypto.Cipher import AES
from Crypto.Random.random import randint
from Crypto.Util.Padding import pad,unpad
import random
import hashlib
import base64
import time


def encrypt(buffer:bytes,key:str) -> bytes:
    iv = random.randbytes(16)
    hashkey = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(hashkey,AES.MODE_CBC,iv)
    ciphertext = cipher.encrypt(pad(buffer,AES.block_size))
    return iv+ciphertext

def decrypt(buffer:bytes,key:str) -> bytes:
    hashkey = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(hashkey,AES.MODE_CBC,iv=buffer[:16])
    try:
        text = unpad(cipher.decrypt(buffer[16:]),AES.block_size)
    except ValueError:
        print("Wrong password")
        time.sleep(4)
        return
    return text

def files_encrypt(path:str,key:str):
    if os.path.isfile(path):
        raw = open(path,"rb").read()
        encrypted_file = encrypt(raw,key)
        try:
            encrypted_file_path = open(f"{os.path.dirname(path)}\\encrypted_files\\{os.path.splitext(os.path.basename(path))[0] + ".encrypted" + os.path.splitext(os.path.basename(path))[1]}","wb").write(encrypted_file)
        except FileNotFoundError:
            os.mkdir(f"{os.path.dirname(path)}\\encrypted_files")
            encrypted_file_path = open(f"{os.path.dirname(path)}\\encrypted_files\\{os.path.splitext(os.path.basename(path))[0] + ".encrypted" + os.path.splitext(os.path.basename(path))[1]}","wb").write(encrypted_file)
        return f"{os.path.dirname(path)}\\encrypted_files\\{os.path.splitext(os.path.basename(path))[0] + ".encrypted" + os.path.splitext(os.path.basename(path))[1]}"
    
    elif os.path.exists(path):
        paths = []
        for root,dirs,files in os.walk(path):
            for file in files:
                if not "encrypted_files" in os.path.join(root,file):
                    file_read = open(os.path.join(root,file), "rb").read()
                    encrypted_file = encrypt(file_read,key)
                    if not os.path.exists(f"{root}\\encrypted_files"):
                        os.mkdir(f"{root}\\encrypted_files")
                        encrypted_file_path = open(f"{root}\\encrypted_files\\{os.path.splitext(os.path.basename(file))[0] + ".encrypted" + os.path.splitext(os.path.basename(file))[1]}","wb").write(encrypted_file)
                        paths.append(f"{root}\\encrypted_files\\{os.path.splitext(os.path.basename(file))[0] + ".encrypted" + os.path.splitext(os.path.basename(file))[1]}")
                    else:
                        encrypted_file_path = open(f"{root}\\encrypted_files\\{os.path.splitext(os.path.basename(file))[0] + ".encrypted" + os.path.splitext(os.path.basename(file))[1]}","wb").write(encrypted_file)
                        paths.append(f"{root}\\encrypted_files\\{os.path.splitext(os.path.basename(file))[0] + ".encrypted" + os.path.splitext(os.path.basename(file))[1]}")
                else:
                    continue
    else:
        return 1
    return paths
    
    
def files_decrypt(path:str,key:str):
    if os.path.isfile(path):
        raw = open(path,"rb").read()
        decrypted_file = decrypt(raw,key)
        try:
            decrypted_file_path = open(f"{os.path.dirname(path)}\\decrypted_files\\{os.path.basename(path).replace(".encrypted","")}","wb").write(decrypted_file)
        except FileNotFoundError:
            os.mkdir(f"{os.path.dirname(path)}\\decrypted_files")
            decrypted_file_path = open(f"{os.path.dirname(path)}\\decrypted_files\\{os.path.basename(path).replace(".encrypted","")}","wb").write(decrypted_file)
        return f"{os.path.dirname(path)}\\decrypted_files\\{os.path.basename(path).replace(".encrypted","")}"
    
    elif os.path.exists(path):
        for root,dirs,files in os.walk(path):
            for file in files:
                    print(root+file)
                    if ".encrypted" in file:
                        file_read = open(os.path.join(root,file), "rb").read()
                        decrypted_file = decrypt(file_read,key)
                        if not os.path.exists(f"{root}\\decrypted_files"):
                            os.mkdir(f"{root}\\decrypted_files")
                            decrypted_file_path = open(f"{root}\\decrypted_files\\{os.path.basename(file).replace(".encrypted","")}","wb").write(decrypted_file)
                        else:
                            decrypted_file_path = open(f"{root}\\decrypted_files\\{os.path.basename(file).replace(".encrypted","")}","wb").write(decrypted_file)
                            
                    else:
                        continue
    else:
        return 1

def container_encrypt(paths,key):
    start_header = b"01010101"
    end_header = b"11100011"
    lengths = []
    names = []

    for path in paths:
        length = len(open(path,"rb").read())
        lengths.append(length)
        name = os.path.basename(path)
        name = base64.b64encode(encrypt(name.encode(),key))
        names.append(name.decode().strip())
    
    
    all = lengths ,names

    with open(f"{os.path.dirname(paths[0])}\\encrypted_container","wb") as file:
        file.write(start_header + str(all).encode() + end_header)

    for path in paths:
        file = open(path, "rb").read()
        with open(f"{os.path.dirname(paths[0])}\\encrypted_container","ab") as file2:
            file2.write(file)
        os.remove(path)



def container_decrypt(path,key):
    end_header = b"11100011"
    chars_to_replace = ["[","]","(",")"]


    with open(path,"rb") as file:
        container_info = file.read()

    end_header_index = container_info.index(end_header)
    info = container_info[8:end_header_index].decode()

    for item in chars_to_replace:
        info = info.replace(item,"")

    info = info.split(",")

    names = []
    lengths = []

    for counter,item in enumerate(info):
            try:
                lengths.append(int(item))
            except ValueError:
                names.append(info[counter])
                
    
    for counter,item in enumerate(names):
        names[counter] = item.replace("'","")
 
    
    for counter,item in enumerate(names):
        names[counter] = decrypt(base64.decodebytes(item.encode()),key).decode().strip()
        
        
        

    
    container_info = container_info[end_header_index+8:]
    try:
        os.mkdir(f"{os.path.dirname(path)}\\decrypted_files")
    except FileExistsError:
        pass
    
    for counter,item in enumerate(lengths):
        shitcheck = sum(lengths[:counter])
        if counter == 0:
            file = container_info[:lengths[0]]
            with open(f"{os.path.dirname(path)}\\decrypted_files\\{names[counter]}","wb") as fila:
                fila.write(decrypt(file,key))
        else:
            file = container_info[shitcheck:item + shitcheck]
            with open(f"{os.path.dirname(path)}\\decrypted_files\\{names[counter]}","wb") as fila:
                fila.write(decrypt(file,key))

def container_viewer(path,key):
    end_header = b"11100011"
    chars_to_replace = ["[","]","(",")"]
    names = []
    lengths = []
    with open(path,"rb") as file:
        container_info = file.read()

    end_header_index = container_info.index(end_header)
    info = container_info[8:end_header_index].decode()

    for item in chars_to_replace:
        info = info.replace(item,"")

    info = info.split(",")

    for counter,item in enumerate(info):
            try:
                lengths.append(int(item))
            except ValueError:
                names.append(info[counter])

    for counter,item in enumerate(names):
        names[counter] = item.replace("'","")

    for counter,item in enumerate(names):
        try:
            if lengths[counter] / 1048576 >= 1000:
                print(f"Size: {round(lengths[counter] / 1073741824,2)} gb","Name: ",decrypt(base64.decodebytes(item.encode()),key).decode().strip())
            elif lengths[counter] / 1048576 >= 1 and lengths[counter] / 1048576 <= 999:
                print(f"Size: {round(lengths[counter] / 1048576,2)} mb","Name: ",decrypt(base64.decodebytes(item.encode()),key).decode().strip())
            elif lengths[counter] / 1048576 <= 1:
                print(f"Size: {round(lengths[counter] / 1024,2)} kb","Name: ",decrypt(base64.decodebytes(item.encode()),key).decode().strip())
        except BaseException:
            print(item)

def settings():
    while True:
        first = input("E - Encrypt path or file\nD - Decrypt path or file\nCE - Encrypt path into a single encrypted container\nCD - Decrypt encrypted container\nSC - Show information about container\n")
        if first.lower() == "e":
            path = input("Please enter a path: ")
            key = input("Please enter a key: ")
            files_encrypt(path,key)
        elif first.lower() == "d":
            path = input("Please enter a path: ")
            key = input("Please enter a key: ")
            files_decrypt(path,key)
        elif first.lower() == "c":
            path = input("Please enter a path: ")
            key = input("Please enter a key: ")
            container_encrypt(files_encrypt(path,key))
        elif first.lower() == "ce":
            path = input("Please enter a path: ")
            key = input("Please enter a key: ")
            container_encrypt(files_encrypt(path,key),key)
        elif first.lower() == "cd":
            path = input("Please enter a path: ")
            key = input("Please enter a key: ")
            container_decrypt(path,key)
        elif first.lower() == "sc":
            path = input("Please enter a path: ")
            key = input("Please enter a key: ")
            container_viewer(path,key)
        else:
            print("Incorrect")
            
            
    
settings()

