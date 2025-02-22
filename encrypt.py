import json
from random import randint
from math import gcd
import sys #n
import numpy as np #n

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
    #print(main(sys.argv[1]))