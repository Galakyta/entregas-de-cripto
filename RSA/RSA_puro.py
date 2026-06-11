'''exponeciacao modular rapida, na teoria o maior problema do rsa seria que calcular m^e mod e mn onde e e n sao numeros enormes, seria meio impossivel, por isso a gente usa exponencial e multiplicacao'''
import random  


#conversoes basicas pra int e string que eu preciso pra fazer o zap zap dps 
def str_to_int(s):
    return int.from_bytes(s.encode('utf-8'), 'big')

def int_to_str(n):
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big').decode('utf-8')

def mod_pow(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if (exp % 2) == 1:  # bit menos significativo é 1
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result
# a ideia disso aq seria pegar esse e enorme, e fazer apenas o log dele, entao isso vira so umas 20 operacoes ao inves
# de uma caralhada delas

def gcd_extendido(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = gcd_extendido(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e, phi):
    gcd, x, _ = gcd_extendido(e, phi)
    if gcd != 1:
        print("e e phi precisam ser primos")
        exit(1)

    return x % phi

def miller_rabin(n, k = 10):
    if n < 4:
        return n > 1
    if n % 2 == 0:
        return False
    r, d = 0, n -1
    while d % 2 == 0:
        r += 1;
        d //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def genprime(bits):
    while True:
        p = random.getrandbits(bits) | (1 << bits - 1) | 1  # força ímpar e MSB=1
        if miller_rabin(p):
            return p

def keygen(bits=512):
    p, q = genprime(bits // 2), genprime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return (e, n), (d, n)  # (pub, priv)

def encrypt(m, pub):
    e, n = pub
    return mod_pow(m, e, n)

def decrypt(c, priv):
    d, n = priv
    return mod_pow(c, d, n)

def encrypt_text(text, pub):
    _, n = pub
    chunk_size = (n.bit_length() // 8) - 1  # minha margem de seguranca
    data = text.encode('utf-8')
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    return [encrypt(int.from_bytes(c, 'big'), pub) for c in chunks]

def decrypt_text(cipherchunks, priv, pub):
    _, n = pub
    chunk_size = (n.bit_length() // 8) - 1
    parts = []
    for c in cipherchunks:
        m = decrypt(c, priv)
        # isso aq é pra chunkar fixo, ou acaba dando NULLNULLNULLNULL no output # 
        if c != cipherchunks[-1]:
            parts.append(m.to_bytes(chunk_size, 'big'))
        else:
            length = (m.bit_length() + 7) // 8
            parts.append(m.to_bytes(length, 'big'))
    return b''.join(parts).decode('utf-8')


if __name__ == "__main__":
    pub, priv = keygen(512)

    msg = 42
    c = encrypt(msg, pub)
    m = decrypt(c, priv)

    print(f"Original: {msg}, Decifrado: {m}")

    pub, priv = keygen(512)

    msg = "if dreams can come true what does that say about nightmares"

    cifrado = encrypt_text(msg, pub)
    decifrado = decrypt_text(cifrado, priv, pub)

    print(f"original: {msg}")
    print(f"decifrado: {decifrado}")
    
    #ordem de execucao
#precisa abrir um terminal pra cada um, é só abrir uns 4 open in integrated terminal pra facilitar
#python server.py
#python usuario.py patata 8001
#python usuario.py patati 8002
#python patatonto.py