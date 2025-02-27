import sys
import json
import itertools
import nltk
import os
import io
from nltk.corpus import words
from collections import Counter
import math
from math import gcd
import numpy as np #n
from Crypto.Cipher import AES #n
from Crypto.Util.Padding import unpad #n
from Crypto.Cipher import DES #n
from Crypto.PublicKey import DSA #n
from Crypto.Signature import DSS #n
from Crypto.Hash import SHA256, HMAC, SHA1 #n
from Crypto.Util import Counter as Ctr #n
from PIL import Image #n
import base64 #n

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
    #value = value.upper()
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
    #if matrix.shape[0] != matrix.shape[1] or np.linalg.det(matrix) % 2 == 0 or np.linalg.det(matrix) % 13 == 0:
    if matrix.shape[0] != matrix.shape[1] or gcd(int(round(np.linalg.det(matrix))),26)!=1:
        return "Invalid key"

    # Calculate inverse matrix modulo 26
    try:
        inv_matrix = matrix_modulo_inverse(matrix, 26)
    except:
        return "Matrix is not invertible modulo 26"

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

    return new_value

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

    return new_value

def decrypt_AES(encrypted_str: str, key: str, iv:str,  mode: str) -> str:
    """
    Decrypts AES encrypted text from a base64 string.

    Args:
        encrypted_str (str): Combined IV and ciphertext string from encrypt_AES
        key_str (str): Base64 encoded key string
        mode (str): AES mode used for encryption
    """

    # Decode the components
    iv = base64.b64decode(iv)
    ciphertext = base64.b64decode(encrypted_str)
    key = key.encode('utf-8')
    if len(key) < 16:
        key = key.ljust(16, b'\0')
    elif len(key) < 24:
        key = key[:16]
    elif len(key) < 32:
        key = key[:24]
    else:
        key = key[:32]

    # Create cipher object based on mode
    if mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif mode == 'CFB':
        cipher = AES.new(key, AES.MODE_CFB, iv)
    elif mode == 'OFB':
        cipher = AES.new(key, AES.MODE_OFB, iv)
    elif mode == 'CTR':
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
    elif mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)

    # Decrypt and unpad
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode('utf-8')

def decrypt_DES(encrypted_str: str, key: str, iv: str, mode: str) -> str:
    """
    Decrypts DES encrypted text from a base64 string.

    Args:
        encrypted_str (str): Base64 encoded ciphertext
        key (str): Encryption key
        iv (str): Base64 encoded IV
        mode (str): DES mode used for encryption

    Returns:
        tuple: (decrypted_text, None)
    """
    # Decode the components
    iv = base64.b64decode(iv)
    ciphertext = base64.b64decode(encrypted_str)

    key = key.encode('utf-8')
    if len(key) < 8:
        key = key.ljust(8, b'\0')
    else:
        key = key[:8]

    # Create cipher object based on mode
    if mode == 'CBC':
        cipher = DES.new(key, DES.MODE_CBC, iv)
    elif mode == 'CFB':
        cipher = DES.new(key, DES.MODE_CFB, iv)
    elif mode == 'OFB':
        cipher = DES.new(key, DES.MODE_OFB, iv)
    elif mode == 'CTR':
        cipher = DES.new(key, DES.MODE_CTR, nonce=iv[:4])
    elif mode == 'ECB':
        cipher = DES.new(key, DES.MODE_ECB)
    else:
        raise ValueError("Invalid mode. Use 'CBC', 'CFB', 'OFB', 'CTR', or 'ECB'")

    decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return decrypted.decode('utf-8')

def decrypt_DSA(signature: str, message: str, public_key: str) -> str:
    """
    Verifies a DSA signature.

    Args:
        signature (str): Base64 encoded signature
        message (str): Original message
        public_key (str): Base64 encoded public key

    Returns:
        tuple: (verification_result, None)
    """
    try:
        # Decode the public key and signature from base64
        public_key_pem = base64.b64decode(public_key)
        signature = base64.b64decode(signature)

        # Import the public key
        key = DSA.import_key(public_key_pem)

        # Create the hash object
        hash_obj = SHA256.new(message.encode('utf-8'))

        # Verify the signature
        verifier = DSS.new(key, 'fips-186-3')
        try:
            verifier.verify(hash_obj, signature)
            return "Signature is valid"
        except ValueError:
            return "Signature is invalid"

    except Exception as e:
        return f"Error in DSA verification: {str(e)}"

def decrypt_ElGammal(encrypted_b64: str, private_key_b64: str) -> str:
    """
    Decrypts El Gamal encrypted text.

    Args:
        encrypted_b64 (str): Base64 encoded encrypted data
        private_key_b64 (str): Base64 encoded private key

    Returns:
        tuple: (decrypted_text, None)
    """
    try:
        # Decode from base64 and parse JSON
        encrypted_data = json.loads(base64.b64decode(encrypted_b64).decode())
        private_key = json.loads(base64.b64decode(private_key_b64).decode())

        # Extract values
        c1 = int(encrypted_data["c1"])
        c2 = int(encrypted_data["c2"])
        p = int(private_key["p"])
        x = int(private_key["x"])

        # Calculate s = c1^x mod p
        s = pow(c1, x, p)

        # Calculate s_inverse = s^(p-2) mod p
        s_inverse = pow(s, p-2, p)

        # Recover M = c2 * s_inverse mod p
        M = (c2 * s_inverse) % p

        # Convert number back to text
        decrypted_text = ""
        while M > 0:
            char_code = M % 1000
            decrypted_text = chr(char_code) + decrypted_text
            M //= 1000

        return decrypted_text

    except Exception as e:
        return f"Error in El Gamal decryption: {str(e)}"

def decrypt_image(input_image_path, output_image_path, key, unique_iv):
  # Read the IV from the separate file
    key = key.encode('utf-8')
    if len(key) < 16:
        key = key.ljust(16, b'\0')
    elif len(key) < 24:
        key = key[:16]
    elif len(key) < 32:
        key = key[:24]
    else:
        key = key[:32]

    # Read the encrypted data
    with open(input_image_path, 'rb') as f:
        encrypted_data = f.read()
    # Separate the IV from the encrypted data
    iv = encrypted_data[:AES.block_size]
    encrypted_data = encrypted_data[AES.block_size:]
    # Initialize AES cipher
    cipher = AES.new(key, AES.MODE_CBC, unique_iv)
    # Decrypt the image data
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    # Convert decrypted bytes to image
    decrypted_image = Image.open(io.BytesIO(decrypted_data))
    # Save the decrypted image
    decrypted_image.save(output_image_path, format=decrypted_image.format)
    print(f"Decryption successful. Decrypted image saved to '{output_image_path}'.")
    return output_image_path

def verify_file_DSA(file_path: str, signature: str, public_key: str) -> tuple:
    """
    Verifies a DSA signature for a file.
    
    Args:
        file_path (str): Path to the file to verify
        signature (str): Base64 encoded signature
        public_key (str): Base64 encoded public key
    
    Returns:
        tuple: (verification_result, None)
    """
    try:
        # Read the file in binary mode
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        # Decode the public key and signature from base64
        public_key_pem = base64.b64decode(public_key)
        signature = base64.b64decode(signature)
        
        # Import the public key
        key = DSA.import_key(public_key_pem)
        
        # Create the hash object
        hash_obj = SHA256.new(file_data)
        
        # Verify the signature
        verifier = DSS.new(key, 'fips-186-3')
        try:
            verifier.verify(hash_obj, signature)
            return "Signature is valid", None
        except ValueError:
            return "Signature is invalid", None
            
    except Exception as e:
        return f"Error in DSA file verification: {str(e)}", None

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

    res = { 'Decrypted text': '',
            'Best coincidence': '',
            'Brutteforce': [],
            'Validity': ''
            }

    if method == 'caesar':
        res['Brutteforce'], res['Best coincidence'] = decrypt_caesar(text)
    elif method == 'affine':
        res['Brutteforce'], res['Best coincidence'] = decrypt_afin(text)
    elif method == 'multiplicative':
        res['Brutteforce'], res['Best coincidence'] = decrypt_multiplicative(text)
    elif method == 'rsa':
        res['Decrypted text'] = decrypt_RSA(text, int(params['n']), int(params['privateKey']))
    elif method == 'permutation':
        res['Brutteforce'], res['Best coincidence'] = decrypt_permutation(text, int(params['m']))
    elif method == 'hill':
        res['Decrypted text'] = decrypt_hill(text, params['matrix'])
    elif method == 'vigenere':
        res['Decrypted text'] = decrypt_vigenere(text, params['key'])
    elif method == 'aes':
        res['Decrypted text']  = decrypt_AES(text, params['key'], params['IV'], params['mode'])
    elif method == 'des':
        res['Decrypted text']  = decrypt_DES(text, params['key'], params['IV'], params['mode'])
    elif method == 'dsa':
        res['Validity']  = decrypt_DSA(params['signature'], text, params['publicKey'])
    elif method == 'elgammal':
        res['Decrypted text']  = decrypt_ElGammal(text, params['privateKey'])
    elif method == 'image':
        result, best = decrypt_image(params['input_image_path'], params['output_image_path'], params['key'], params['iv'])

    return res

if __name__ == "__main__":
    main()