import os
from time import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def generate_aes_key(key_size):
    key = os.urandom(key_size // 8)
    with open(f'aes_key_{key_size}.key', 'wb') as f:
        f.write(key)
    return key


def load_aes_key(key_size):
    with open(f'aes_key_{key_size}.key', 'rb') as f:
        return f.read()


def aes_encrypt_decrypt(operation, key, data, mode='ECB'):
    if mode == 'ECB':
        cipher_mode = modes.ECB()
    elif mode == 'CFB':
        cipher_mode = modes.CFB(key[:16])
    cipher = Cipher(algorithms.AES(key), cipher_mode, backend=default_backend())
    cryptor = cipher.encryptor() if operation == 'encrypt' else cipher.decryptor()
    return cryptor.update(data) + cryptor.finalize()


def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    with open('rsa_private_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                          format=serialization.PrivateFormat.PKCS8,
                                          encryption_algorithm=serialization.NoEncryption()))
    with open('rsa_public_key.pem', 'wb') as f:
        f.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    return private_key, public_key


def load_rsa_keys():
    with open('rsa_private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open('rsa_public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    return private_key, public_key


def rsa_encrypt_decrypt(operation, key, data):
    if operation == 'encrypt':
        return key.encrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    else:
        return key.decrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))


def rsa_sign_verify(operation, private_key, public_key, data):
    if operation == 'sign':
        signature = private_key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        with open('rsa_signature.sig', 'wb') as f:
            f.write(signature)
        return signature
    else:
        with open('rsa_signature.sig', 'rb') as f:
            signature = f.read()
        public_key.verify(signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())


def sha256_hash(file_path):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            digest.update(chunk)
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
        with open('encrypted_aes_data.bin', 'wb') as f:
            f.write(encrypted_data)
        print(f"Encrypted: {encrypted_data}, Time: {enc_time}s")
        with open('encrypted_aes_data.bin', 'rb') as f:
            encrypted_data = f.read()
        decrypted_data, dec_time = measure_time(aes_encrypt_decrypt, 'decrypt', key, encrypted_data, mode)
        print(f"Decrypted: {decrypted_data.decode()}, Time: {dec_time}s")
    elif choice == '2':
        private_key, public_key = generate_rsa_keys()
        data = input("Enter data to encrypt: ").encode()
        encrypted_data, enc_time = measure_time(rsa_encrypt_decrypt, 'encrypt', public_key, data)
        with open('encrypted_rsa_data.bin', 'wb') as f:
            f.write(encrypted_data)
        print(f"Encrypted: {encrypted_data}, Time: {enc_time}s")
        with open('encrypted_rsa_data.bin', 'rb') as f:
            encrypted_data = f.read()
        decrypted_data, dec_time = measure_time(rsa_encrypt_decrypt, 'decrypt', private_key, encrypted_data)
        print(f"Decrypted: {decrypted_data.decode()}, Time: {dec_time}s")
    elif choice == '3':
        private_key, public_key = generate_rsa_keys()
        data = input("Enter data to sign: ").encode()
        signature, sign_time = measure_time(rsa_sign_verify, 'sign', private_key, public_key, data)
        print(f"Signature: {signature}, Time: {sign_time}s")
        try:
            rsa_sign_verify('verify', private_key, public_key, data)
            print("Verification successful")
        except Exception as e:
            print(f"Verification failed: {e}")
    elif choice == '4':
        file_path = input("Enter file path for hashing: ")
        hash_result, hash_time = measure_time(sha256_hash, file_path)
        print(f"SHA-256 Hash: {hash_result.hex()}, Time: {hash_time}s")


if __name__ == "__main__":
    main()