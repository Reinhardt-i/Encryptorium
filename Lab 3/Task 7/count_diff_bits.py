

def hex_to_bin(hex_str: str) -> bin:
    return bin(int(hex_str, 16))[2:].zfill(8 * len(hex_str))


def count_same_bits(str1 : bin, str2 : bin) -> int:
    return sum(bit1 == bit2 for bit1, bit2 in zip(str1, str2))


if __name__ == '__main__':

    hash1_md5, hash2_md5 = 'ecb0643fc6f7472dee6eff566dab7a0c', '46caa6a5d48e2c9ad2b623c6c3e40b8a'
    hash1_sha256, hash2_sha256 = 'fe70754ed6a845ba1ce32870bb6f20cc00fb28c114a6db6706af7defa10354ed', 'a889f7ad60264552ffe272f058a08f273676146674b229496976543056020822'

    same_bits_md5 = count_same_bits(hex_to_bin(hash1_md5), hex_to_bin(hash2_md5))
    same_bits_sha256 = count_same_bits(hex_to_bin(hash1_sha256), hex_to_bin(hash2_sha256))
    

    print(f"Same bits in MD5 hashes: {same_bits_md5}")
    print(f"Same bits in SHA256 hashes: {same_bits_sha256}")

result = "Same bits in MD5 hashes: 190, Same bits in SHA256 hashes: 379"