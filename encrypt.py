import json
from random import randint
from math import gcd
import sys #n
import numpy as np #n
from Crypto.Cipher import AES #n
from Crypto.Util.Padding import pad #n
from Crypto.Random import get_random_bytes #n
from Crypto.Cipher import DES #n
import base64 #n

def encrypt_caesar(text: str, a: int) -> str:

    text = text.upper()
    new_text = ""

    for char in text:
        n_char = ord(char)
        if n_char == 32: continue
        new_text += chr(((n_char - 65 + a) % 26) + 65)

    return new_text, None, None

def encrypt_affine(text: str, a: int, b: int) -> str:

    text = text.upper()
    new_text = ""

    for char in text:
        n_char = ord(char)
        #if key_a % 2 == 0 or key_a == 13: continue
        if n_char == 13: continue
        new_text += chr((((a * (n_char - 65)) + b) % 26) + 65)

    return new_text, None, None

def encrypt_multiplicative(text: str, a: int) -> str:

    text = text.upper()
    new_text = ''

    for char in text:
        n_char = ord(char)
        if n_char == 32: continue
        new_text += chr((((n_char - 65) * a) % 26) + 65)

    return new_text, None, None

def find_keys(p,q):

    n = p*q
    phi_n = (p-1) * (q-1) #Ya que phi(p*q) = phi(p) * phi(q) = (p-1)*(q-1) al ser p,q primos
    a = randint(2,int(phi_n/2))
    while True:
        if gcd(a, phi_n) == 1:
            break
        a += 1
    b = 2
    while True:
        if (b * a) % phi_n == 1:
            break
        b += 1

    return a,b

def encrypt_RSA(text: str, p: int, q: int):

    n = p * q
    a,b = find_keys(p,q)

    text = text.upper()
    new_text = ''

    for char in text:
        n_char = ord(char)
        if n_char == 32: continue
        new_text += str(((n_char - 65)**a % n) + 65) + " "
    #! Retorna el valor ASCII de cada letra en el mensaje encriptado, para que se imprima mejor en el front.
    #print(new_text)
    #print(n_char, a)
    return new_text, a, b

def encrypt_permutation(text: str, m: str, pi:str) -> str:
    #pi tiene la forma "3 1 0 2"
    pi = [int(x) for x in pi.split()]
    m = int(m)

    text = text.upper()
    new_text = ''

    #Se rellena con letras aleatorias para que el mensaje tenga un tamaño múltiplo de m
    while len(text) % m != 0:
        text += chr(randint(65, 65+25))

    for i in range(0, len(text)):
        numero_en_grupo = i % m
        numero_de_bloque =  m * (i // m)
        new_text += text[pi[numero_en_grupo] + numero_de_bloque]

    return new_text, None, None

def encrypt_hill(text: str, key: str) -> str:
    # Convert key string to numpy matrix
    matrix = np.matrix(key)
    m = matrix.shape[0]  # Get matrix size (m x m)
    
    # Validate key matrix
    if matrix.shape[0] != matrix.shape[1] or np.linalg.det(matrix) % 2 == 0 or np.linalg.det(matrix) % 13 == 0:
        return "Invalid key", None, None

    text = text.upper()
    new_text = ''
    
    # Pad text with random letters to make it divisible by matrix size
    while len(text) % m != 0:
        text += chr(randint(65, 65+25))
    
    # Process text in blocks of size m
    for i in range(0, len(text), m):
        # Convert block of letters to number vector (0-25)
        block = np.zeros(m, dtype=int)
        for j in range(m):
            block[j] = ord(text[i + j]) - 65
            
        # Multiply key matrix with block vector and take modulo 26
        result = np.dot(matrix, block) % 26
        
        # Convert numbers back to letters
        for num in result.flat:
            new_text += chr(int(num) + 65)

    return new_text, None, None

def encrypt_vigenere(text: str, key: str) -> str:
    text = text.upper()
    key = key.upper()
    new_text = ''
    extended_key = ''
    for i in range(len(text)):
        if text[i] == ' ':
            continue
        extended_key += key[i % len(key)]

    key_pos = 0
    
    for char in text:
        n_char = ord(char)
        if n_char == 32:  # Skip spaces
            continue
            
        shift = ord(extended_key[key_pos]) - 65
    
        new_char = chr(((n_char - 65 + shift) % 26) + 65)
        new_text += new_char
        
        key_pos += 1
        
    return new_text, None, None

def encrypt_AES(text: str, key: str, mode: str) -> str:
    """
    Encrypts text using AES and returns a base64 string containing the ciphertext and IV.
    
    Args:
        text (str): Text to encrypt
        key (str): Encryption key (will be padded/truncated to 16, 24, or 32 bytes)
        mode (str): AES mode ('CBC', 'CFB', 'OFB', 'CTR', 'ECB')
    
    Returns:
        tuple: (encrypted_string, key_string, None)
        encrypted_string format: "base64_encoded_iv:base64_encoded_ciphertext"
    """
    # Prepare the key
    key1 = key
    key = key.encode('utf-8')
    if len(key) < 16:
        key = key.ljust(16, b'\0')
    elif len(key) < 24:
        key = key[:16]
    elif len(key) < 32:
        key = key[:24]
    else:
        key = key[:32]

    # Convert text to bytes
    text = text.encode('utf-8')
    
    # Generate IV
    iv = get_random_bytes(16)
    
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
        iv = b''  # No IV for ECB
    else:
        raise ValueError("Invalid mode. Use 'CBC', 'CFB', 'OFB', 'CTR', or 'ECB'")

    # Encrypt and pad the text
    ciphertext = cipher.encrypt(pad(text, AES.block_size))
    
    # Combine IV and ciphertext and encode to base64
    iv_b64 = base64.b64encode(iv).decode('utf-8')
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
    
    # Return the combined string and encoded key
    return ciphertext_b64, key1, iv_b64

def encrypt_DES(text: str, key: str, mode: str) -> str:
    """
    Encrypts text using DES and returns a base64 string containing the ciphertext and IV.
    
    Args:
        text (str): Text to encrypt
        key (str): Encryption key (will be padded/truncated to 8 bytes)
        mode (str): DES mode ('CBC', 'CFB', 'OFB', 'CTR', 'ECB')
    
    Returns:
        tuple: (encrypted_string, key_string, iv_string)
        encrypted_string format: base64 encoded ciphertext
    """
    # Ajustarlo a 8 bytes
    key1 = key
    key = key.encode('utf-8')
    if len(key) < 8:
        key = key.ljust(8, b'\0')
    else:
        key = key[:8]

    text = text.encode('utf-8')
    
    iv = get_random_bytes(8)
    
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
        iv = b''  # No IV for ECB
    else:
        raise ValueError("Invalid mode. Use 'CBC', 'CFB', 'OFB', 'CTR', or 'ECB'")

    ciphertext = cipher.encrypt(pad(text, DES.block_size))
    
    # Encode to base64
    iv_b64 = base64.b64encode(iv).decode('utf-8')
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
    
    return ciphertext_b64, key1, iv_b64
    
def main2(method: str, text: str, params: dict) -> str:
    if method == 'caesar':
        new_text, p1, p2 = encrypt_caesar(text, int(params['a']))
    elif method == 'affine':
        new_text, p1, p2 = encrypt_affine(text, int(params['a']), int(params['b']))
    elif method == 'multiplicative':
        new_text, p1, p2 = encrypt_multiplicative(text, int(params['a']))
    elif method == 'rsa':
        new_text, p1, p2 = encrypt_RSA(text, int(params['p']), int(params['q']))
    elif method == 'permutation':
        new_text, p1, p2 = encrypt_permutation(text, params['m'], params['pi'])
    elif method == 'hill':
        new_text, p1, p2 = encrypt_hill(text, params['key'])
    elif method == 'vigenere':
        new_text, p1, p2 = encrypt_vigenere(text, params['key'])
    elif method == 'aes':
        new_text, p1, p2 = encrypt_AES(text, params['key'], params['mode'])
    elif method == 'des':
        new_text, p1, p2 = encrypt_DES(text, params['key'], params['mode'])
        


    return new_text, p1, p2
def main(json_str: str) -> str:
    data = json.loads(json_str)

    text = data['text']
    method = data['method']
    params = data['params']

    new_text = ""

    if method == 'caesar':
        new_text, p1, p2 = encrypt_caesar(text, int(params['a']))
    elif method == 'affine':
        new_text, p1, p2 = encrypt_affine(text, int(params['a']), int(params['b']))
    elif method == 'multiplicative':
        new_text, p1, p2 = encrypt_multiplicative(text, int(params['a']))
    elif method == 'rsa':
        new_text, p1, p2 = encrypt_RSA(text, int(params['p']), int(params['q']))
    elif method == 'permutation':
        new_text, p1, p2 = encrypt_permutation(text, params['m'], params['pi'])
    elif method == 'hill':
        new_text, p1, p2 = encrypt_hill(text, params['key'])
    elif method == 'vigenere':
        new_text, p1, p2 = encrypt_vigenere(text, params['key'])
    elif method == 'aes':
        new_text, p1, p2 = encrypt_AES(text, params['key'], params['mode'])
    elif method == 'des':
        new_text, p1, p2 = encrypt_DES(text, params['key'], params['mode'])
        


    return new_text, p1, p2

if __name__ == "__main__":
    method = input("Method: ")
    text = input("Text: ")
    if method == 'rsa':
        p = int(input("p: "))
        q = int(input("q: "))
        print(main2(method, text, {'p': p, 'q': q}))
    elif method == 'caesar':
        a = int(input("a: "))
        print(main2(method, text, {'a': a}))
    elif method == 'affine':
        a = int(input("a: "))
        b = int(input("b: "))
        print(main2(method, text, {'a': a, 'b': b}))
    elif method == 'multiplicative':
        a = int(input("a: "))
        print(main2(method, text, {'a': a}))
    elif method == 'permutation':
        m = input("m: ")
        pi = input("pi: ")
        print(main2(method, text, {'m': m, 'pi': pi}))
    elif method == 'hill':
        key = input("Key: ")
        print(main2(method, text, {'key': key}))
    elif method == 'vigenere':
        key = input("Key: ")
        print(main2(method, text, {'key': key}))
    elif method == 'aes':
        key = input("Key: ")
        mode = input("Mode: ")
        print(main2(method, text, {'key': key, 'mode': mode}))
    elif method == 'des':
        key = input("Key: ")
        mode = input("Mode: ")
        print(main2(method, text, {'key': key, 'mode': mode}))
    #print(main(sys.argv[1]))