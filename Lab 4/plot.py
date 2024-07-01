import matplotlib.pyplot as plt
import main.py


def plot_execution_times():
    aes_key_sizes = [16, 32, 64, 128, 256]  # in bytes
    rsa_key_sizes = [512, 1024, 2048, 4096]  # in bits
    
    aes_enc_times = []
    aes_dec_times = []
    rsa_enc_times = []
    rsa_dec_times = []
    
    data = b"This is a test data."
    
    # Measure AES encryption/decryption times for different key sizes
    for key_size in aes_key_sizes:
        key = generate_aes_key(key_size * 8)  # key_size in bits
        enc_data, enc_time = measure_time(aes_encrypt_decrypt, 'encrypt', key, data, 'ECB')
        aes_enc_times.append(enc_time)
        dec_data, dec_time = measure_time(aes_encrypt_decrypt, 'decrypt', key, enc_data, 'ECB')
        aes_dec_times.append(dec_time)
    
    # Generate RSA keys for different key sizes and measure encryption/decryption times
    for key_size in rsa_key_sizes:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
        public_key = private_key.public_key()
        enc_data, enc_time = measure_time(rsa_encrypt_decrypt, 'encrypt', public_key, data)
        rsa_enc_times.append(enc_time)
        dec_data, dec_time = measure_time(rsa_encrypt_decrypt, 'decrypt', private_key, enc_data)
        rsa_dec_times.append(dec_time)
    
    # Plotting AES times
    plt.figure()
    plt.plot(aes_key_sizes, aes_enc_times, label='AES Encryption')
    plt.plot(aes_key_sizes, aes_dec_times, label='AES Decryption')
    plt.xlabel('Key Size (bytes)')
    plt.ylabel('Time (seconds)')
    plt.title('AES Encryption/Decryption Times')
    plt.legend()
    plt.grid(True)
    plt.show()

    # Plotting RSA times
    plt.figure()
    plt.plot(rsa_key_sizes, rsa_enc_times, label='RSA Encryption')
    plt.plot(rsa_key_sizes, rsa_dec_times, label='RSA Decryption')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Time (seconds)')
    plt.title('RSA Encryption/Decryption Times')
    plt.legend()
    plt.grid(True)
    plt.show()