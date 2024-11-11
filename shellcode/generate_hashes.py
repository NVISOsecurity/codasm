import random

def hash_djb2(s: str):
    hash = 5381
    for x in s:
        hash = ((hash << 5) + hash) + ord(x)
    return hash & 0xFFFFFFFF

crypt_key = random.randint(0, 0xFFFFFFFF)

with open("api_resolve.h", "r") as _file:
    contents = _file.read(-1)

hashes = f'#define CRYPT_KEY {hex(crypt_key)}\n'
hashes += f'#define CRYPTED_HASH_KERNEL32 {hex(hash_djb2("KERNEL32.DLL".lower()) ^ crypt_key)}\n'
hashes += f'#define CRYTPED_HASH_CREATETHREAD {hex(hash_djb2("CreateThread") ^ crypt_key)}\n'
hashes += f'#define CRYPTED_HASH_LOADLIBRARYA {hex(hash_djb2("LoadLibraryA") ^ crypt_key)}\n'
hashes += f'#define CRYPTED_HASH_VIRTUALALLOC {hex(hash_djb2("VirtualAlloc") ^ crypt_key)}\n'
hashes += f'#define CRYPTED_HASH_VIRTUALFREE {hex(hash_djb2("VirtualFree") ^ crypt_key)}\n'
hashes += f'#define CRYPTED_HASH_VIRTUALPROTECT {hex(hash_djb2("VirtualProtect") ^ crypt_key)}\n'

hashes += f'#define CRYPTED_HASH_SHLWAPI {hex(hash_djb2("Shlwapi.DLL".lower()) ^ crypt_key)}\n'
hashes += f'#define CRYPTED_HASH_STRSTRA {hex(hash_djb2("StrStrA") ^ crypt_key)}\n'

with open("api_resolve.h", "w") as _file:
    _file.write(contents.replace("//%HASHES%", hashes))