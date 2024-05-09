from typing import Dict, Tuple, List

class CipherDecipher:

    def __init__(self):
        """
            Initializes the frequency dictionary for the English language.
        """
        self.frequency = {
            'a': 8.05, 'b': 1.67, 'c': 2.23, 'd': 5.10, 'e': 12.22, 'f': 2.14, 'g': 2.30,
            'h': 6.62, 'i': 6.28, 'j': 0.19, 'k': 0.95, 'l': 4.08, 'm': 2.33, 'n': 6.95,
            'o': 7.63, 'p': 1.66, 'q': 0.06, 'r': 5.29, 's': 6.02, 't': 9.67, 'u': 2.92,
            'v': 0.82, 'w': 2.60, 'x': 0.11, 'y': 2.04, 'z': 0.06
        }


    def decipher_cipher_frequency(self, ciphertext: str) -> str:
        """
            Deciphers a ciphertext by mapping its frequency to English letter frequency.

            Args:
            ciphertext (str): The text to be deciphered.

            Returns:
            str: The deciphered text.
        """
        cipher_frequency: Dict[str, int] = {}
        for char in ciphertext.lower():
            if char.isalpha():
                cipher_frequency[char] = cipher_frequency.get(char, 0) + 1

        cipher_vec: List[Tuple[str, int]] = sorted(cipher_frequency.items(), key=lambda item: item[1], reverse=True)
        freq_vec: List[Tuple[str, float]] = sorted(self.frequency.items(), key=lambda item: item[1], reverse=True)

        char_map: Dict[str, str] = {}
        for (c1, _), (c2, _) in zip(cipher_vec, freq_vec):
            char_map[c1] = c2

        decrypted_text: str = ''
        for char in ciphertext:
            if char.isalpha():
                decrypted_text += char_map.get(char.lower(), char)
            else:
                decrypted_text += char

        return decrypted_text


    def decipher_cipher_key(self, ciphertext: str, key: str) -> str:
        """
            Deciphers a ciphertext using a specific key.

            Args:
            ciphertext (str): The text to be deciphered.
            key (str): The key to use for decryption.

            Returns:
            str: The deciphered text.
        """
        alphabet = [chr(x) for x in range(ord('a'), ord('z')+1)] 
        char_map: Dict[str, str] = {alphabet[i]: key[i] for i in range(len(key))}

        decrypted_text: str = ''
        for char in ciphertext:
            if char.isalpha():
                decrypted_text += char_map.get(char.lower(), char)
            else:
                decrypted_text += char

        return decrypted_text



if __name__ == '__main__':

    decipher = CipherDecipher()

    text_to_break_1 = "af p xpkcaqvnpk pfg, af ipqe qpri, gauuikifc tpw, ceiri udvk tiki afgarxifrphni cd eao-wvmd popkwn, hiqpvri du ear jvaql vfgikrcpfgafm du cei xkafqaxnir du xrwqedearcdkw pfg du ear aopmafpcasi xkdhafmr afcd fit pkipr. ac tpr qdoudkcafm cd lfdt cepc au pfwceafm epxxifig cd ringdf eaorinu hiudki cei opceiopcaqr du cei uaing qdvng hi qdoxnicinw tdklig dvc- pfg edt rndtnw ac xkdqiigig, pfg edt odvfcpafdvr cei dhrcpqnir--ceiki tdvng pc niprc kiopaf dfi mddg oafg cepc tdvng qdfcafvi cei kiripkqe"
    text_to_break_2 = "aceah toz puvg vcdl omj puvg yudqecov, omj loj auum klu thmjuv hs klu zlcvu shv zcbkg guovz, upuv zcmdu lcz vuwovroaeu jczoyyuovomdu omj qmubyudkuj vukqvm. klu vcdluz lu loj avhqnlk aodr svhw lcz kvopuez loj mht audhwu o ehdoe eunumj, omj ck toz yhyqeoveg auecupuj, tlokupuv klu hej sher wcnlk zog, klok klu lcee ok aon umj toz sqee hs kqmmuez zkqssuj tckl kvuozqvu. omj cs klok toz mhk umhqnl shv sowu, kluvu toz oezh lcz yvhehmnuj pcnhqv kh wovpue ok. kcwu thvu hm, aqk ck zuuwuj kh lopu eckkeu ussudk hm wv. aonncmz. ok mcmukg lu toz wqdl klu zowu oz ok scskg. ok mcmukg-mcmu klug aunom kh doee lcw tuee-yvuzuvpuj; aqk qmdlomnuj thqej lopu auum muovuv klu wovr. kluvu tuvu zhwu klok zlhhr klucv luojz omj klhqnlk klcz toz khh wqdl hs o nhhj klcmn; ck zuuwuj qmsocv klok omghmu zlhqej yhzzuzz (oyyovumkeg) yuvyukqoe ghqkl oz tuee oz (vuyqkujeg) cmubloqzkcaeu tuoekl. ck tcee lopu kh au yocj shv, klug zocj. ck czm'k mokqvoe, omj kvhqaeu tcee dhwu hs ck! aqk zh sov kvhqaeu loj mhk dhwu; omj oz wv. aonncmz toz numuvhqz tckl lcz whmug, whzk yuhyeu tuvu tceecmn kh shvncpu lcw lcz hjjckcuz omj lcz nhhj shvkqmu. lu vuwocmuj hm pczckcmn kuvwz tckl lcz vueokcpuz (ubduyk, hs dhqvzu, klu zodrpceeu-aonncmzuz), omj lu loj womg juphkuj ojwcvuvz owhmn klu lhaackz hs yhhv omj qmcwyhvkomk sowcecuz. aqk lu loj mh dehzu svcumjz, qmkce zhwu hs lcz ghqmnuv dhqzcmz aunom kh nvht qy. klu uejuzk hs kluzu, omj aceah'z sophqvcku, toz ghqmn svhjh aonncmz. tlum aceah toz mcmukg-mcmu lu ojhykuj svhjh oz lcz lucv, omj avhqnlk lcw kh ecpu ok aon umj; omj klu lhyuz hs klu zodrpceeu- aonncmzuz tuvu scmoeeg jozluj. aceah omj svhjh loyyumuj kh lopu klu zowu acvkljog, zuykuwauv 22mj. ghq loj aukkuv dhwu omj ecpu luvu, svhjh wg eoj, zocj aceah hmu jog; omj klum tu dom dueuavoku hqv acvkljog-dhwshvkoae yovkcuz g khnukluv. ok klok kcwu svhjh toz zkcee cm lcz ktuumz, oz klu lhaackz doeeuj klu cvvuzyhmzcaeu ktumkcuz auktuum dlcejlhhj omj dhwcmn hs onu ok klcvkg-klvuu"

    # These keys were found using an online decryptor since frequency analysis wasn't accurate enough.
    key1, key2 = "ixtohndbeqrkglmacsvwfuypjz", "bxiclqyozdthngavukfwermjps"
    # I've tried to custom mapping in real time to change the keys gotten from freq analysis, but I couldn't do it, kept getting errors, left those code in debug segment. Please Ignore.

    print(f"\nFirst, Cipher Text 1 to decrypt : {text_to_break_1[0:20]}....\n")
    print(f"Decryption of text 1 with Frequency analysis : \n{decipher.decipher_cipher_frequency(text_to_break_1)}\n\n")
    print(f"\nDecryption of text 1 with Decryptor Keys : \n{decipher.decipher_cipher_key(text_to_break_1, key1)}\n\n\n\n ")

    print(f"Now, Cipher Text 2 to decrypt : {text_to_break_2[0:20]}....\n")
    print(f"Decryption of text 2 with Frequency analysis: \n{decipher.decipher_cipher_frequency(text_to_break_2)}\n\n")
    print(f"\nDecryption of text 2 with Decryptor Keys : \n{decipher.decipher_cipher_key(text_to_break_2, key2)}\n\n\n\n ")





'''

# DEBUG :

from collections import Counter
import re

def decrypt_substitution_cipher(ciphertext, custom_mappings=None):

    letters = re.sub('[^a-z]', '', ciphertext.lower())
    frequency, sorted_freq = Counter(letters), sorted(frequency.items(), key=lambda x: -x[1])
    eng_freq_order = 'etaoinshrdlcumwfgypbvkjxqz'
    
    cipher_to_eng = {}
    for i, (char, _) in enumerate(sorted_freq):
        cipher_to_eng[char] = eng_freq_order[i]

    if custom_mappings:
        cipher_to_eng.update(custom_mappings)

    decrypted_text = ''.join(cipher_to_eng.get(char, char) for char in ciphertext.lower())

    return decrypted_text, cipher_to_eng


decrypted_text1, key1 = decrypt_substitution_cipher(ciphertext1)  # without custom mappings
print(f"Initial Decryption: {decrypted_text1}")
print(f"Initial Key: {key1}")

custom_mappings = {'a': 'o', 'f': 'e'}  # applying a specific adjustment
decrypted_text1_adjusted, key1_adjusted = decrypt_substitution_cipher(ciphertext1, custom_mappings)

print(f"\nAdjusted Decryption: {decrypted_text1_adjusted}")
print("Adjusted Key: {key1_adjusted}")


'''