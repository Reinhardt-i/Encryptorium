
from collections import Counter

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



def decrypt_substitution_cipher(encrypted_text):
    
    eng_freq_order = 'etaoinshrdlcumwfgypbvkjxqz'  # English letter frequency roughly sorted by frequency
    
    counter = Counter([char for char in encrypted_text if char.isalpha()])
    total_chars = sum(counter.values())
    freq_list = sorted(counter.items(), key=lambda x: x[1], reverse=True)
    
    # Map most frequent letter in cipher to most frequent letter in English
    cipher_to_eng = {}
    for i, (char, count) in enumerate(freq_list):
        cipher_to_eng[char] = eng_freq_order[i % len(eng_freq_order)]
    

    decrypted_text = ''.join(cipher_to_eng.get(char, char) for char in encrypted_text)
    
    return decrypted_text, cipher_to_eng



encrypted_text = cipher_sub_2
decrypted_text, key = decrypt_substitution_cipher(encrypted_text)
print("Decryption Key:", key)
print("Decrypted Text:", decrypted_text)




# DEBUGG

def interactive_decrypt(encrypted_text, cipher_to_eng):
    decrypted_text = ''.join(cipher_to_eng.get(char, char) for char in encrypted_text)
    print("Decrypted Text:", decrypted_text)
    while True:
        print("Current Key:", cipher_to_eng)
        change = input("Enter letter to change and new letter (e.g., 'x:e'): ")
        if change == "done":
            break
        old, new = change.split(':')
        for key, value in cipher_to_eng.items():
            if value == old:
                cipher_to_eng[key] = new
        decrypted_text = ''.join(cipher_to_eng.get(char, char) for char in encrypted_text)
        print("Updated Text:", decrypted_text)


cipher_to_eng = {'i': 'e', 'd': 't', 'c': 'a', 'p': 'o', 'a': 'i', 'f': 'n', 'r': 's', 'e': 'h', 'k': 'r', 'g': 'd', 'n': 'l', 'q': 'c', 'v': 'u', 'u': 'm', 't': 'w', 'o': 'f', 'x': 'g', 'w': 'y', 'm': 'p', 'h': 'b', 'l': 'v', 'j': 'k', 's': 'j'}
encrypted_text = "your encrypted text here"
interactive_decrypt(encrypted_text, cipher_to_eng)
