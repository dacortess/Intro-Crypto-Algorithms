import json

def encrypt_caesar(text: str, a: int) -> str:

    text = text.upper()
    new_text = ""

    for char in text:
        n_char = ord(char)
        if n_char == 32: continue
        new_text += chr(((n_char - 65 + a) % 26) + 65)

    return new_text

def encrypt_affine(text: str, a: int, b: int) -> str:

    text = text.upper()
    new_text = ""

    for char in text:
        n_char = ord(char)
        #if key_a % 2 == 0 or key_a == 13: continue
        if n_char == 13: continue
        new_text += chr((((a * (n_char - 65)) + b) % 26) + 65)

    return new_text

def encrypt_multiplicative(text: str, a: int) -> str:

    text = text.upper()
    new_text = ''

    for char in text:
        n_char = ord(char)
        if n_char == 32: continue
        new_text += chr((((n_char - 65) * a) % 26) + 65)

    return new_text

def find_keys(p,q):
    from random import randint
    from math import gcd

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
    return new_text

def encrypt_permutation(text: str, m: str, pi:str) -> str:
    from random import randint

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

    return new_text

def main(json_str: str) -> str:
    data = json.loads(json_str)

    text = data['text']
    method = data['method']
    params = data['params']

    new_text = ""

    if method == 'caesar':
        new_text = encrypt_caesar(text, int(params['a']))
    elif method == 'affine':
        new_text = encrypt_affine(text, int(params['a']), int(params['b']))
    elif method == 'multiplicative':
        new_text = encrypt_multiplicative(text, int(params['a']))
    elif method == 'rsa':
        new_text = encrypt_RSA(text, int(params['p']), int(params['q']))
    elif method == 'permutation':
        new_text = encrypt_permutation(text, params['m'], params['pi'])


    return new_text

if __name__ == "__main__":
    print(main(sys.argv[1]))