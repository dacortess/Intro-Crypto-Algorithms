import sys
import json
import itertools
import nltk
from nltk.corpus import words
from collections import Counter
import math
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
    return new_value

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

    return result, best

if __name__ == "__main__":
    main()