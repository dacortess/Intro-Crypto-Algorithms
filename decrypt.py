import sys
import json
import itertools
import nltk
from nltk.corpus import words
from collections import Counter
import math
import numpy as np #n
nltk.download('words')

def decrypt_caesar(value: str) -> str:
    value = value.upper()
    possible_values = list()

    for key in range(1,26):
        new_value = ''
        for char in value:
            n_char = ord(char)
            if n_char == 32: continue
            new_value += chr(((n_char - 65 - key) % 26) + 65)
        possible_values.append((str(new_value), str(key)))
        
    mejor_palabra = get_most_english_string_letter_freq([x[0] for x in possible_values])
    return possible_values, mejor_palabra

def decrypt_afin(value: str) -> str:

    def inverso(num: int) -> int:
        for inv in range(0,26):
            if (num*inv) % 26 == 1:
                return inv

    value = value.upper()
    possible_values = list()

    for key_a in range(1,25):
        if key_a % 2 == 0 or key_a == 13: continue
        for key_b in range(1,25):
            new_value = ''
            for char in value:
                n_char = ord(char)
                if n_char == 32: continue
                new_value += chr(((key_a * (n_char - 65 - key_b)) % 26) + 65)
            
            possible_values.append((str(new_value), str(inverso(key_a)), str(key_b)))

    mejor_palabra = get_most_english_string_letter_freq([x[0] for x in possible_values])
    return possible_values, mejor_palabra

def decrypt_RSA(value: str, n:int, b:str) ->str:
    pass
    value = value.upper()
    new_value = ''
    n = int(n)
    b = int(b)
    for char in value.split():
        char = int(char)
        if char == 32: continue
        new_value += chr(((char - 65)**b % n) + 65)
    return new_value, new_value

def decrypt_permutation(value:str, m:str) -> str:
    #List all the inverse permutations
    m = int(m)
    value = value.upper()
    values = list()
    new_value = ''
    
    if len(value) % m != 0:
        value += "X" * (m - len(value) % m)
    possible_permutations = list(itertools.permutations([x for x in range(0,m)]))
    for perm in possible_permutations:
        for i in range(0,len(value),m):
            for j in range(m):
                new_value += value[i + perm[j]]
        inv_perm = " ".join([str(x) for x in perm])
        values.append((new_value, f"inverse perm = {inv_perm}"))
        new_value = ''
    
    mejor_palabra = get_most_english_string_ngram([x[0] for x in values])
    return values, mejor_palabra

def decrypt_multiplicative(value: str) -> str:
    value = value.upper()
    possible_values = list()

    # Find multiplicative inverse for keys from 1 to 25
    for key in range(1, 26):
        # Check if the key is coprime with 26 (has a multiplicative inverse)
        if math.gcd(key, 26) == 1:
            # Find the multiplicative inverse
            inv_key = pow(key, -1, 26)
            new_value = ''
            for char in value:
                n_char = ord(char)
                if n_char == 32:  # Skip spaces
                    continue
                # Decrypt using the multiplicative inverse
                new_value += chr(((n_char - 65) * inv_key % 26) + 65)
            possible_values.append((str(new_value), str(key)))

    if not possible_values:
        return [], None
    
    # Find the most likely English string
    mejor_palabra = get_most_english_string_letter_freq([x[0] for x in possible_values])
    return possible_values, mejor_palabra

def modular_multiplicative_inverse(a, m):
    """Helper function to find modular multiplicative inverse"""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    _, x, _ = extended_gcd(a, m)
    return (x % m + m) % m

def matrix_modulo_inverse(matrix, modulus):
    """Calculate the inverse of a matrix in modulo 26"""
    # Convert to integer matrix
    matrix = matrix.astype(int)
    
    # Calculate determinant and its modular multiplicative inverse
    det = int(round(np.linalg.det(matrix))) % modulus
    det_inv = modular_multiplicative_inverse(det, modulus)
    
    # Calculate adjugate matrix
    adj = np.round(np.linalg.det(matrix) * np.linalg.inv(matrix)).astype(int)
    
    # Calculate inverse modulo 26
    inv_matrix = (det_inv * adj) % modulus
    return inv_matrix

def decrypt_hill(value: str, key: str) -> str:
    # Convert key string to numpy matrix
    matrix = np.matrix(key)
    m = matrix.shape[0]  # Get matrix size (m x m)
    
    # Validate key matrix
    if matrix.shape[0] != matrix.shape[1] or np.linalg.det(matrix) % 2 == 0 or np.linalg.det(matrix) % 13 == 0:
        return "Invalid key", None
    
    # Calculate inverse matrix modulo 26
    try:
        inv_matrix = matrix_modulo_inverse(matrix, 26)
    except:
        return "Matrix is not invertible modulo 26", None
    
    value = value.upper()
    new_value = ''
    
    # Process text in blocks of size m
    for i in range(0, len(value), m):
        block = np.zeros(m, dtype=int)
        for j in range(m):
            if i + j < len(value):
                block[j] = ord(value[i + j]) - 65
        
        result = np.dot(inv_matrix, block) % 26
        
        for num in result.flat:
            new_value += chr(int(num) + 65)
    
    return new_value, new_value
    
def decrypt_vigenere(value: str, key: str) -> str:
    value = value.upper()
    key = key.upper()
    new_value = ''
    extended_key = ''
    for i in range(len(value)):
        if value[i] == ' ':
            continue
        extended_key += key[i % len(key)]

    key_pos = 0
    
    for char in value:
        n_char = ord(char)
        if n_char == 32:  # Skip spaces
            continue
            
        shift = ord(extended_key[key_pos]) - 65
    
        new_char = chr(((n_char - 65 - shift) % 26) + 65)
        new_value += new_char
        
        key_pos += 1
        
    return new_value, new_value

def train_ngram_model(corpus, n=3):
    model = Counter()
    for word in corpus:
        word = word.lower()
        for i in range(len(word) - n + 1):
            ngram = word[i:i+n]
            model[ngram] += 1
    total_ngrams = sum(model.values())
    for ngram in model:
        model[ngram] /= total_ngrams
    return model

def ngram_score(string, model, n=3):
    score = 0
    string = string.lower()
    for i in range(len(string) - n + 1):
        ngram = string[i:i+n]
        if ngram in model:
            score += math.log(model[ngram])
        else:
            score += math.log(1e-10) 
    return score

def get_most_english_string_ngram(strings):
    english_words = words.words()
    bigram_model = train_ngram_model(english_words, n=3)
    scores = {string: ngram_score(string, bigram_model) for string in strings}
    return max(scores, key=scores.get)

english_letter_freq = {
    'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97,
    'n': 6.75, 's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25,
    'l': 4.03, 'c': 2.78, 'u': 2.76, 'm': 2.41, 'w': 2.36,
    'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.29,
    'v': 0.98, 'k': 0.77, 'x': 0.15, 'j': 0.15, 'q': 0.10, 'z': 0.07
}

def letter_score(string):
    score = 0
    for char in string.lower():
        score += english_letter_freq.get(char, 0)
    return score

def get_most_english_string_letter_freq(strings):
    return max(strings, key=letter_score)


#####################################
#####       ONLY FOR DEBUG      #####
#####################################

def main2(method: str, text: str, params: dict) -> str:
    if method == 'caesar':
        new_text, p1 = decrypt_caesar(text)
    elif method == 'affine':
        new_text, p1 = decrypt_afin(text)
    elif method == 'multiplicative':
        new_text, p1 = decrypt_multiplicative(text)
    elif method == 'rsa':
        new_text, p1 = decrypt_RSA(text, int(params['n']), int(params['pk']))
    elif method == 'permutation':
        new_text, p1 = decrypt_permutation(text, int(params['m']))
    elif method == 'hill':
        new_text, p1 = decrypt_hill(text, params['key'])
    elif method == 'vigenere':
        new_text, p1 = decrypt_vigenere(text, params['key'])
    
    return new_text, p1

def main(json_str):
    data = json.loads(json_str)

    text = data['text']
    method = data['method']
    params = data['params']

    result = ""

    if method == 'caesar':
        result, best = decrypt_caesar(text)
    elif method == 'affine':
        result, best = decrypt_afin(text)
    elif method == 'multiplicative':
        result, best = decrypt_multiplicative(text)
    elif method == 'rsa':
        result, best = decrypt_RSA(text, int(params['n']), int(params['pk']))
    elif method == 'permutation':
        result, best = decrypt_permutation(text, int(params['m']))
    elif method == 'hill':
        result, best = decrypt_hill(text, params['key'])
    elif method == 'vigenere':
        result, best = decrypt_vigenere(text, params['key'])

    return result, best

if __name__ == "__main__":
    method = input("Method: ")
    text = input("Text: ")
    if method == 'rsa':
        n = int(input("n: "))
        pk = int(input("pk: "))
        print(main2(method, text, {'n': n, 'pk': pk}))
    elif method == 'caesar':
        print(main2(method, text, {}))
    elif method == 'affine':
        print(main2(method, text, {}))
    elif method == 'multiplicative':
        print(main2(method, text, {}))
    elif method == 'permutation':
        m = int(input("m: "))
        print(main2(method, text, {'m': m}))
    elif method == 'hill':
        key = input("key: ")
        print(main2(method, text, {'key': key}))
    elif method == 'vigenere':
        key = input("key: ")
        print(main2(method, text, {'key': key}))
    else:
        print("Invalid method")
        sys.exit(1)
    #main()