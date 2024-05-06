# For the second problem, we have to deal with a substitution cipher.
# We can attempt a simple frequency analysis to guess the substitutions based on English letter frequencies.
# First, we'll write a function to count the frequency of each character in a cipher.

def frequency_analysis(ciphertext):

    frequencies = {}
    total_letters = 0 

    for char in ciphertext:
        if char.isalpha():
            if char in frequencies:
                frequencies[char] += 1
            else:
                frequencies[char] = 1
            total_letters += 1

    for letter in frequencies:
        frequencies[letter] = (frequencies[letter] / total_letters) * 100

    return dict(sorted(frequencies.items(), key=lambda item: item[1], reverse=True))


# Two ciphers given in the problem
cipher_sub_1 = ("af p xpkcaqvnpk pfg, af ipqe qpri, gauuikifc tpw, ceiri udvk tiki afgarxifrphni cd eao-"
                "wvmd popkwn, hiqpvri du ear jvaql vfgikrcpfgafm du cei xkafqaxnir du xrwqedearcdkw pfg "
                "du ear aopmafpcasi xkdhafmr afcd fit pkipr. ac tpr qdoudkcafm cd lfdt cepc au pfwceafm "
                "epxxifig cd ringdf eaorinu hiudki cei opceiopcaqr du cei uaing qdvng hi qdoxnicinw tdklig dvc-"
                "pfg edt rndtnw ac xkdqiigig, pfg edt odvfcpafdvr cei dhrcpqnir--ceiki tdvng pc niprc kiopaf dfi "
                "mddg oafg cepc tdvng qdfcafvi cei kiripkqe")

cipher_sub_2 = ("aceah toz puvg vcdl omj puvg yudqecov, omj loj auum klu thmjuv hs klu zlcvu shv "
                "zcbkg guovz, upuv zcmdu lcz vuwovroaeu jczoyyuovomdu omj qmubyudkuj vukqvm. klu "
                "vcdluz lu loj avhqnlk aodr svhw lcz kvopuez loj mht audhwu o ehdoe eunumj, omj ck toz "
                "yhyqeoveg auecupuj, tlokupuv klu hej sher wcnlk zog, klok klu lcee ok aon umj toz sqee hs "
                "kqmmuez zkqssuj tckl kvuozqvu. omj cs klok toz mhk umhqnl shv sowu, kluvu toz oezh lcz "
                "yvhehmnuj pcnhqv kh wovpue ok. kcwu thvu hm, aqk ck zuuwuj kh lopu eckkeu ussudk hm "
                "wv. aonncmz. ok mcmukg lu toz wqdl klu zowu oz ok scskg. ok mcmukg-mcmu klug aunom kh "
                "doee lcw tuee-yvuzuvpuj; aqk qmdlomnuj thqej lopu auum muovuv klu wovr. kluvu tuvu zhwu "
                "klok zlhhr klucv luojz omj klhqnlk klcz toz khh wqdl hs o nhhj klcmn; ck zuuwuj qmsocv klok")

# Calculate frequencies for both ciphers
frequency_1 = frequency_analysis(cipher_sub_1)
frequency_2 = frequency_analysis(cipher_sub_2)


# print(frequency_1)
# print(frequency_2)


def map_frequencies(cipher_freq, english_freq):
    sorted_cipher = sorted(cipher_freq.items(), key=lambda item: item[1], reverse=True)
    sorted_english = sorted(english_freq.items(), key=lambda item: item[1], reverse=True)
    
    mapping = {}
    for cipher_char, english_char in zip(sorted_cipher, sorted_english):
        mapping[cipher_char[0]] = english_char[0]
    
    return mapping

def decrypt(ciphertext, mapping):
    plaintext = ''
    for char in ciphertext:
        if char in mapping:
            plaintext += mapping[char]
        else:
            plaintext += char
    return plaintext

english_frequencies = {
    'a': 8.05, 'b': 1.67, 'c': 2.23, 'd': 5.10, 'e': 12.22, 'f': 2.14,
    'g': 2.30, 'h': 6.62, 'i': 6.28, 'j': 0.19, 'k': 0.95, 'l': 4.08,
    'm': 2.33, 'n': 6.95, 'o': 7.63, 'p': 1.66, 'q': 0.06, 'r': 5.29,
    's': 6.02, 't': 9.67, 'u': 2.92, 'v': 0.82, 'w': 2.60, 'x': 0.11,
    'y': 2.04, 'z': 0.06
}

cipher_frequencies = {
    'i': 11.33, 'd': 8.87, 'c': 8.13, 'p': 7.88, 'a': 7.64, 'f': 7.39, 'r': 5.67,
    'e': 5.42, 'k': 4.68, 'g': 4.68, 'n': 3.94, 'q': 3.69, 'v': 3.20, 'u': 3.20,
    't': 2.71, 'o': 2.71, 'x': 2.46, 'w': 1.97, 'm': 1.72, 'h': 1.48, 'l': 0.74,
    'j': 0.25, 's': 0.25
}

mapping = map_frequencies(cipher_frequencies, english_frequencies)
ciphertext = cipher_sub_2
decrypted_text = decrypt(ciphertext, mapping)

print(decrypted_text)
