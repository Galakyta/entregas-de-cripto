import hashlib # bibilioteca padrao, n tem mt oq eu falar creo djo
import os # os é usada aqui pra gerar bytes aleatorios pro salt


S_BOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

RCON = [
    0x01,0x02,0x04,0x08,
    0x10,0x20,0x40,0x80,
    0x1b,0x36,0x6c,0xd8,
    0xab,0x4d,0x9a
] 

#funcao que transforma o nosso bloco de dados, que pode ser uma senha ou simplesmente uma frase em uma matriz de 16 bytes, o aes sempre usa 16 bytes para funcionamento interno então ela precisa
#necessariamente sofrer um processo para receber padding
def texto_para_blocos(texto):
    dados = texto.encode()  #encode transforma tudo em utf 8 por padrao, mas se pode usar outros padroes
    resto = len(dados) % 16  # o resto é divido por 16 pra saber se paddingg é necessario
    if resto != 0: #se for diferente de 0 precisa de padding
        dados += b'\x00' * (16 - resto) # esse b'\x00' representa um valor nulo, que é interpretado como 0 paddinhg, e aplicado onde nao tem dados e precisa de padding
    return [list(dados[i:i+16]) for i in range(0, len(dados), 16)]  #retorna uma lista de 4x4, ou como aqui esta explicado 16 partes, 

def gerar_iv():
    return (os.urandom(16)) #iv aleatorio para garantir aleatoriedade, ele não precisa ser confidencial

def xor_blocos(a, b): # o xor entre blocos é relacionado com o metodo de operacao cbc, onde o nosso a e b, sao os blocos que faram xor entre si para aumentar difusao atraves de 1 bloco depender do outro
    #na hora de criptografar os dados, linearmente
    return [x ^ y for x, y in zip(a, b)]

def encrypt_cbc(plaintext_bytes, w, iv): # aqui funciona o encrypt
    blocos = texto_para_blocos(plaintext_bytes) if isinstance(plaintext_bytes, str) else [plaintext_bytes] #os blocos recebem o plaintext
    anterior = iv #iv é tambem chamado de initial vector, q é o começo da nossa cadeia
    resultado = b''
    for bloco in blocos: # para todos os blocos
        xorado = xor_blocos(bloco, list(anterior)) #realiza o xor entre blocos, o primeiro sempre com o iv
        estado = chave_para_estado(xorado) # o estado atual é definido como o resultado do nosso xor entre blocos 
        cifrado = encrypt(estado, w) # w = cofre de senhas derivadas
        cifrado_bytes = estado_para_bytes(cifrado) # vira um estado
        resultado += cifrado_bytes #recebe como resultado
        anterior = cifrado_bytes  # se torna o anterior
    return resultado

def decrypt_cbc(ciphertext_bytes, w, iv):
    resultado = b''
    anterior = list(iv)
    for i in range(0, len(ciphertext_bytes), 16):
        bloco = list(ciphertext_bytes[i:i+16])
        estado = chave_para_estado(bloco)
        decriptado = estado_para_bytes(decrypt(estado, w))  
        xorado = xor_blocos(list(decriptado), anterior)    
        resultado += bytes(xorado)
        anterior = bloco  
    return resultado

def derivar_chave(senha, salt = None):
    if salt is None: #
        salt = os.urandom(16)  # os pra gerar um salt aleatorio
    chave = hashlib.pbkdf2_hmac( #pbbk e hash pra derivar
        'sha256',#motor sha256
        senha.encode(), #senha encodada
        salt, #o salt
        100000, # iteracoes que aumentam o custo computacional
        dklen=32 #tamanho em bytes
    )
    return chave, salt #retorna a chave e o salt pra ser guardado

def estado_para_bytes(estado):
    resultado = []
    for col in range(4):
        for row in range(4):
            resultado.append(estado[row][col]) #pega o estado row por col e transforma em bytes
    return bytes(resultado)
def bytes_p_lista(dados): #bytes pra lista
    return list(dados)

def chave_para_estado(chave):
    estado = [[0] * 4 for _ in range(4)] #pega a chave, indexa, e transforma em matriz 4x4
    for i in range (16):
        row = i % 4
        col = i // 4
        estado[row][col] = chave[i]
    return estado

def adicionar_roundkey(estado, roundkey):
    for i in range(4):
        for j in range(4): #simplesmente adiciona a roundkey ja aplicando o xor
            estado[i][j] ^= roundkey[i][j]
    return estado


def sub_bytes(estado):
    for i in range(4):
        for j in range(4):
                estado[i][j] = S_BOX[estado[i][j]] # pega o indice e substitui
    return estado # como da pra ver aqui é uma operação simples de subsituição pela lookup tabble, 

def shift_rows(estado):
    for i in range(1, 4):
        estado[i] = estado[i][i:] + estado[i][:i] # slicer
    return estado


def gmul(a, b): 
    p = 0 
    for _ in range(8): # 8 pois é 1 byte checando bit a bit
        if b & 1:
            p ^= a # se for 1 tem um xor com a

        high_bit = a & 0x80 # define o bit
        a = (a << 1) & 0xFF #faz o shift
        if high_bit:
            
            a ^= 0x1b
        
        b >>= 1 
    return p 

def mix_columns(estado): 
    for j in range(4):
        a0 = estado[0][j] # aqui a gente pega todos os valores da coluna 1 2 3 e 4
        a1 = estado[1][j]
        a2 = estado[2][j]
        a3 = estado[3][j]

        estado[0][j] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3 
        estado[1][j] = a0 ^ gmul(a1, 2) ^ gmul(a2,3) ^ a3 
        estado[2][j] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3) 
        estado[3][j] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2) 
    return estado  

def rot_excord(word):
    return word[1:] + word[:1]

def sub_word(word):
    return [S_BOX[b] for b in word]


def key_expansion_256(chave):
    w = []

    # 8 words iniciais que são 32 bytes, 
    for i in range(8):
        w.append(chave[4*i:4*(i+1)]) # isso aq só fatia a chave de 32 origignal em 4 partes de 8 doferemtes

    for i in range(8, 60): # dai vc pensa porra 60 words é coisa pra caralho, e é mesmo mas ta de boa pq na vdd vc so ta gerando 60 words pq precisa de 15 round keys e 1 a mais lembra

        temp = w[i-1].copy() #dai a gente via ter 3 opcoes, depois da gente começar com a word anterior que ta no nosso w copiada

        if i % 8 == 0: # aqui tem um detalhe importante, porque a egnt eprecisa de 2 informacoes, se a word     que ta sendo gerada for a primeira do ciclo de geracao
            #ou se ela ta exatamente no meio do ciclo, isso importa porque a ggente precisa introduzir não linearidade, entao a gente faz uma transformacao completa
            # e a elif ==4 é pq o aes 256 exige uma transformacao extra de subbox, pq como a chave maior preicsa de uma camada a mais de nao linearidade
            temp = rot_excord(temp) # 1 rotacao de slice
            temp = sub_word(temp) # 1 substituicaao
            temp[0] ^= RCON[(i//8)-1] # 1 passada pelo rcon .. importante pontuar que aq precisa dividir por 8 pra gente saber em qual ciclo a gente ta, isso e o 
            # byte é o 0 fixamente pra evitar simetria, só passos em cima de passos de linearidade

        elif i % 8 == 4:
            temp = sub_word(temp) # ja comentei

        new_word = []
        for j in range(4):
            new_word.append(w[i-8][j] ^ temp[j]) # depois dessa putaria toda finalmente a nova word [e criada appendando  as colunas do tempo, e isso se repete pra uma word depender da proxima]
          

        w.append(new_word)   # ja que o w ta levando um apend da word

    return w


def get_round_key(w, round):
    key = []
    for i in range(4):
        key += w[round*4 + i]
    return chave_para_estado(key)



def encrypt(estado, w):

    estado = adicionar_roundkey(estado, get_round_key(w, 0))

    for rodada in range(1, 14):
        estado = sub_bytes(estado)
        estado = shift_rows(estado)
        estado = mix_columns(estado)
        estado = adicionar_roundkey(estado, get_round_key(w, rodada))

    estado = sub_bytes(estado)
    estado = shift_rows(estado)
    estado = adicionar_roundkey(estado, get_round_key(w, 14))

    return estado

INV_S_BOX = [0]*256

for i in range (256):
    INV_S_BOX[S_BOX[i]] = i

def inv_sub_bytes(estado):
    for i in range(4):
        for j in range(4):
            estado[i][j] = INV_S_BOX[estado[i][j]]
    return estado

def inv_shift_rows(estado):
    for i in range(1, 4):
        estado[i] = estado[i][-i:] + estado[i][:-i]
    return estado

def inv_mix_columns(estado):
    for j in range(4):
        a0 = estado[0][j]
        a1 = estado[1][j]
        a2 = estado[2][j]
        a3 = estado[3][j]

        estado[0][j] = gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9)
        estado[1][j] = gmul(a0,9)  ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13)
        estado[2][j] = gmul(a0,13) ^ gmul(a1,9)  ^ gmul(a2,14) ^ gmul(a3,11)
        estado[3][j] = gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9)  ^ gmul(a3,14)
        
    return estado

def decrypt(estado, w):

    estado = adicionar_roundkey(estado, get_round_key(w, 14))

    for rodada in range(13, 0, -1):
        estado = inv_shift_rows(estado)
        estado = inv_sub_bytes(estado)
        estado = adicionar_roundkey(estado, get_round_key(w, rodada))
        estado = inv_mix_columns(estado)

    estado = inv_shift_rows(estado)
    estado = inv_sub_bytes(estado)
    estado = adicionar_roundkey(estado, get_round_key(w, 0))

    return estado



if __name__ == "__main__":

    cofre = "cofre.txt"

    senha_mestre = input("Senha mestre: ")

    while True:
        opcao = input("\n1 - adiconar senha\n 2 - abrir cofre\n 0 - sair\n")

        if opcao == "1":
            site = input("Site: ")
            senha = input("Senha do site")

            dados = senha 
            tamanho_da_senha = len(senha)
            tamanho_da_senha_em_bytes = bytes([tamanho_da_senha >> 8, tamanho_da_senha & 0xFF])
            chave_bytes, salt = derivar_chave(senha_mestre)
            w = key_expansion_256(list(chave_bytes))
            iv = gerar_iv()

            cifrado_bytes = encrypt_cbc(dados, w, iv)

            with open(cofre, "a") as f:
                f.write(f"{site}|{salt.hex()}|{iv.hex()}|{cifrado_bytes.hex()}|{tamanho_da_senha_em_bytes.hex()}\n")

            print(f"[+] '{site}' salvo.")

        elif opcao == "2":
            if not os.path.exists(cofre):
                print("Cofre vazio")
                continue
            linhas = []
            with open(cofre, "r") as f:
                for linha in f:
                    site, salt_hex, iv_hex, cifrado_hex, tamanho_hex = linha.strip().split("|")

                    salt          = bytes.fromhex(salt_hex)
                    iv            = list(bytes.fromhex(iv_hex))
                    cifrado_bytes = bytes.fromhex(cifrado_hex)
                    tamanho_bytes = bytes.fromhex(tamanho_hex)

                    tamanho_original = (tamanho_bytes[0] << 8 | tamanho_bytes[1])

                    chave_bytes, _ = derivar_chave(senha_mestre, salt)
                    w = key_expansion_256(list(chave_bytes))

                    senha = decrypt_cbc(cifrado_bytes, w, iv)[:tamanho_original].decode()
                    #originalmente feito com rstrip
                    linhas.append(f"{site}: {senha}")

            with open("cofre_aberto.txt", "w") as f:
                f.write("\n".join(linhas))

            print("[+] cofre_aberto.txt gerado:")
            for l in linhas:
                print(" ", l)

        elif opcao == "0":
            break

            
 


   