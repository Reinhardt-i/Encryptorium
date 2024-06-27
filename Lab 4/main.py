"""
STUFF:
    - https://medium.com/asecuritysite-when-bob-met-alice/python-cryptography-and-hazmat-105aaafc05a9
    - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/

"""



import os
from time import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def generate_aes_key(key_size):
    return os.urandom(key_size // 8)


def aes_encrypt_decrypt(operation, key, data, mode='ECB'):
    if mode == 'ECB':
        cipher_mode = modes.ECB()
    elif mode == 'CFB':
        cipher_mode = modes.CFB(key[:16])
    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
    cryptor = cipher.encryptor() if operation == 'encrypt' else cipher.decryptor()
    return cryptor.update(data) + cryptor.finalize()


def generate_rsa_keys():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())


def rsa_encrypt_decrypt(operation, key, data):
    if operation == 'encrypt':
        return key.encrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    else:
        return key.decrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))


def rsa_sign_verify(operation, private_key, data):
    signer = private_key.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    signer.update(data)
    return signer.finalize()


def sha256_hash(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()


def measure_time(func, *args):
    start_time = time()
    result = func(*args)
    elapsed_time = time() - start_time
    return result, elapsed_time


def main():
    print("Crypto Operation Tool")
    print("1: AES Encryption/Decryption")
    print("2: RSA Encryption/Decryption")
    print("3: RSA Signature")
    print("4: SHA-256 Hashing")
    choice = input("Choose an operation: ")

    if choice == '1':
        key_size = int(input("Enter key size (128 or 256): "))
        mode = input("Enter mode (ECB or CFB): ")
        key = generate_aes_key(key_size)
        data = input("Enter data to encrypt: ").encode()
        encrypted_data, enc_time = measure_time(aes_encrypt_decrypt, 'encrypt', key, data, mode)
        print(f"Encrypted: {encrypted_data}, Time: {enc_time}s")
        decrypted_data, dec_time = measure_time(aes_encrypt_decrypt, 'decrypt', key, encrypted_data, mode)
        print(f"Decrypted: {decrypted_data}, Time: {dec_time}s")
    elif choice == '2':
        # RSA operations and timing...
        pass
    elif choice == '3':
        # RSA signature and verification...
        pass
    elif choice == '4':
        data = input("Enter data for hashing: ").encode()
        hash_result, hash_time = measure_time(sha256_hash, data)
        print(f"SHA-256 Hash: {hash_result}, Time: {hash_time}s")


if __name__ == "__main__":
    main()