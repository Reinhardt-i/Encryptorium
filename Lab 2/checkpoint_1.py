

def decrypt_caesar_cipher(ciphertext: str, shift: int) -> str:

    """
        Decrypts a ciphertext using the Caesar cipher method.

        Args:
        ciphertext (str): The text to be decrypted.
        shift (int): The number of positions each letter in the ciphertext was shifted.

        Returns:
        str: The decrypted text.
    """

    decrypted_text = ""

    for char in ciphertext:
        if char.isalpha():
            
            shifted = ord(char) - shift
            if char.islower():
                if shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted < ord('A'):
                    shifted += 26
            decrypted_text += chr(shifted)

        else:
            decrypted_text += char
    return decrypted_text


def decrypt_caesar_cipher_w_allpossible_shifts(ciphertext: str) -> str:

    """
        Decrypts a ciphertext using the Caesar cipher method while checking all possible 26 shifts.

        Args:
        ciphertext (str): The text to be decrypted.

        Returns:
        str: The decrypted text for all shifts.
    """

    ans = ""

    for i in range (0, 26):
        ans += f"For i = {i}, Decrypted caesar : {decrypt_caesar_cipher(ciphertext, i)} \n"

    return ans



if __name__ == '__main__':

    cipher_caesar_to_break = "odroboewscdrolocdcwkbdmyxdbkmdzvkdpybwyeddrobo"

    # print(decrypt_caesar_cipher_w_allpossible_shifts(cipher_caesar_to_break))
    
    # By Running the line above, found shift = 10 to be meaningful, so ans is -
    
    print(f"The decrypted form of {cipher_caesar_to_break} "
        f"is -\n {decrypt_caesar_cipher(cipher_caesar_to_break, 10)}\n"
        f"[found by applying shift = 10]")
