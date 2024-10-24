from collections import Counter
import string


def create_vigenere_table():
    table = []
    alphabet = string.ascii_uppercase
    for i in range(len(alphabet)):
        row = alphabet[i:] + alphabet[:i]
        table.append(row)
    return table


def kasiski_analysis(ciphertext):
    trigram_positions = {}
    for i in range(len(ciphertext) - 3):
        trigram = ciphertext[i:i + 3]
        if trigram in trigram_positions:
            trigram_positions[trigram].append(i)
        else:
            trigram_positions[trigram] = [i]

    distances = []
    for positions in trigram_positions.values():
        if len(positions) > 1:
            for i in range(1, len(positions)):
                distances.append(positions[i] - positions[i - 1])
    return distances


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def find_key_length(distances):
    if not distances:
        return 1
    g = distances[0]
    for d in distances[1:]:
        g = gcd(g, d)
    return g


def friedman_test(ciphertext):
    n = len(ciphertext)
    freq = Counter(ciphertext)
    ic = sum(v * (v - 1) for v in freq.values()) / (n * (n - 1))
    k = (0.0265 * n) / ((0.065 - ic) + ic * (n - 1))
    return round(k)


def decrypt_vigenere(ciphertext, key):
    vigenere_table = create_vigenere_table()
    plaintext = []
    key_len = len(key)
    key = key.upper()

    for i, char in enumerate(ciphertext):
        if char in string.ascii_uppercase:
            try:
                row = string.ascii_uppercase.index(key[i % key_len])
            except ValueError:
                continue
            col = vigenere_table[row].index(char)
            plaintext.append(string.ascii_uppercase[col])
        else:
            plaintext.append(char)
    return ''.join(plaintext)


def try_decrypt_with_popular_keywords(ciphertext):
    popular_keywords = [
        # "jehla", "osmicka",
        "hope"
    ]

    common_words = ["THE", "AND", "THAT", "WITH", "THIS", "HAVE", "FROM", "YOUR", "NOT", "BUT", "ALL", "FORM", "TION",
                    "NION", "TO", "PUBLIC", "DATA", "WAY", "DOES", "BEEN", "TIAL", "ITY", "OFTH", "OFYUO", "FOR" ]
    possible_keys = []
    for keyword in popular_keywords:
        key = keyword.upper()
        plaintext = decrypt_vigenere(ciphertext, key)
        if any(word in plaintext for word in common_words):
            possible_keys.append((key, plaintext))
    return possible_keys



#  my
# ciphertext1 = "MIJCE JWPYG BXVCA PIJZS CWHYD CLLQL NBPMI UMAJW RXOHH RGODT XVHRE LEUME MIWWO HIKSA EIJSA WKLOT QIZEO AENPL JRKDC JTLEH NJPIE MHPCE LXHNC NWZDT XVHRE MICTC NLHDB NIUCE YPHNE MAPEH BXVCA PIHCE JRLEW XVRDW QMJSH JZLCE MYJPD LSZES JRKLL USDPD JKYPA CHLLL VSYPF UIETB RPPEY RRLYT NVWCI BIZEO AENP"
# ciphertext = "HJMLK DICFM TOOTV GPAQP PIJOP CCIBY EWHDW OJQQP FOZNQ LVREQ MEBQW EFDAI FSNUL TMUYF HOMZG YNHGT QUYWB ZMZFG AFWUV TOTIJ ZNQBA ZAOMP CETWQ BJOCI KFWOO RQGGT FKLGG BCTMH OKQIO KIBLQ VCXCS SSZGO MSFFB QBEQW UDGZA HUTMU DOHZQ AQPTK SDMQB OHZQZ UEPDG DBUOR JAOMU"
ciphertext = "PHTGGOAHRRIHRZODTXPUMAPOYQIPABODIRDDQQDQCGBGMXDXEXHOHOQPXGZXXSQDSAMOVXTIDPZGPSIXAOWAAYAIRX"


ciphertext = ciphertext.replace(" ", "")  # Remove spaces for easier analysis

# Step 1: Kasiski analysis to determine probable key length
distances = kasiski_analysis(ciphertext)
key_length = find_key_length(distances)
if key_length == 1:
    print("Could not determine key length using Kasiski analysis. Trying Friedman test.")
    key_length = friedman_test(ciphertext)
print(f"Estimated key length: {key_length}")

# Step 2: Try to decrypt with popular keywords
possible_keys = try_decrypt_with_popular_keywords(ciphertext)
if possible_keys:
    print("\nPossible decryptions containing common words:")
    for key, plaintext in possible_keys:
        print(f"Key: {key}\nDecrypted text: {plaintext}\n")
else:
    print("\nNo matching decryption found with popular keywords.")