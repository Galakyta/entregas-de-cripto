import os


'''OK vamo la, isso aqui é em geral a minha implementação de aes, que eu decidi posteriormente transformar em um "estudo dirigido" entre uma caralhada de aspas pra servir de estudo
extra e anotações, o aes ta seguindo o padrão que o prof pediu no trabalho e eu vou tentar fazer isso aqui em "capitulos" ou melhor, transformar isso aqui tudo em uma sequencia logica
mais ou menos entendivel, começando com alguns conceitos essenciais para entender o aes

primeiro e talvez mais importante, a gente vai trabalhar com senhas, essas senhas inicialmente podem ser strings de texto, a sua famosa senha123, mas que vao passar por varios proce
ssos para tornalas seguras e impossiveis de se ler, isso é, sem a chave original.

para facilitar isso vamo pensar assim, primeiro, sua senha, vai ser transformada em um bloco de bytes, um 4x4 diga se de passagem, em aes 256 esse bloco da chave tem 16 bytes
igual a aes 128 e 192, isso não muda independente do comprimento da chave, MAS existe claro uma diferença entre eles, pois a chave criptografica que é derivada da sua chave original
muda sim de tamanho, no caso ela varia de 16 24 e 32 respectivamente entre 128 192 e 256, mas isso a gente vai ver mais pra frente, no momento vamos separar esse codio todo da seguinte forma
coisas fixas -> tratamento da entrada -> nucleo de encryptacao -> processo de decryptacao.




comecando pelo que é fixo
'''

'''durante todo esse processo você vai ter 2 matrizes fixas importantes, 1 chamada de substitution box, ou SBOX
    e a round constant RCON, eu to falando delas agora pra ja explicar o ponto que mais definem o aes
    
   não linearidade
   

    o aes tem um design feito pra ser confuso mesmo pro desespero de quem ta aprendendo isso, mas tudo gera em torno de pegar um grupo de dados, e embaralhar eles de forma não linear
    matematicamente, isso que diferencia ela de apenas uma cifra como uma base 64 que é facilmente reversivel

'''



'''o que é a sbox de fato, o componente mais importante do aes que é responsavel por fazer o processo de reversão impossivel sem a chave efetivamente
 ela é só bem, uma tabela, mas que é mapeada pra que cada byte seja mapeado para virar outro byte por substituicao usando uma lookuptable com logica de  inversao multiplicativa de
 gf(2na oitava) usando um polinomio irredutivel (q eu n vo entrar) e depois uma funcao afim usando xor como uma constante, ambas operações matematicas mas que a gente não precisa usar,
   ja que ela ja foi bem definida pela fips pra ser interoperavel '''
S_BOX = [ #padrao da documentacao la q eu esqueci o nome
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

'''agora o rcon, isso aqui é outra parada completamente diferente, é um componente do processo de derivar a chave como dito anteriormente que acontece antes da encryptacao comecar,
 mas que é definido usando gf(2na oito) tambem, todos os valores dele sao calculados como potencias de 2 nesse campo'''

"""em comparacao com a sbox ela é bem menos usada por ser parte da expansao de chave, que é usada para um xor com o primeiro byte de parte da chave para evitar ainda mais a linearidade"""
RCON = [
    0x01,0x02,0x04,0x08,
    0x10,0x20,0x40,0x80,
    0x1b,0x36,0x6c,0xd8,
    0xab,0x4d,0x9a
] 




'''ok com isso fora do caminho a gente pode ir para como os dados vão ser tratados antes da gente poder começar a encryptacao. 

primeiro de tudo, o aes não trabalha com string, então sua senha "esqueciasenha123" não pode ser processada diretamente, ela precisa primeiro ser transformada em um bloco de dados


'''


'''essa é a função que prepara os nossos dados em blocos de 16 bytes que vao passar pelo aes, ela serve para qualquer dado que a gente for passar, pois ele necessariamente precisa ser de 16 bytes'''
def texto_para_blocos(texto):
    dados = texto.encode() if isinstance(texto, str) else bytes(texto) #encoda por padrao pra utf 8, mas tem outras formas de encodar como ascii
    resto = len(dados) % 16 #aqui comeca um segundo processo que indica pro resto do algogritimo se o bloco é multiplo de 16, ou  resto
    if resto != 0: # se sobrar, vai cair aqui
        dados += b'\x00' * (16 - resto) # a gente multiplica por 0, sim esse simbolo estranho é zero, vezes o que falta pra fechar 16
        #apesar de na verdade eu saber, isso é um byte nulo que representaria 0, porque se a gente fizer simplesmente 0 * 16 preciso falar nada
    # fatia em blocos de 16
    return [list(dados[i:i+16]) for i in range(0, len(dados), 16)]  #depois do tratamento, a gente retorna uma lista com o texto 4x4

def gerar_iv():
    return (os.urandom(16))  # 16 bytes aleatórios, igual ao salt

def xor_blocos(a, b):
    return [x ^ y for x, y in zip(a, b)]

def encrypt_cbc(plaintext_bytes, w, iv):
    blocos = texto_para_blocos(plaintext_bytes)
    anterior = iv
    resultado = b''
    for bloco in blocos:
        xorado = xor_blocos(bloco, list(anterior))
        estado = chave_para_estado(xorado)
        cifrado = encrypt(estado, w)
        cifrado_bytes = estado_para_bytes(cifrado)
        resultado += cifrado_bytes
        anterior = cifrado_bytes  # próximo bloco usa este como "IV"
    return resultado

def decrypt_cbc(ciphertext_bytes, w, iv):
    resultado = b''
    anterior = list(iv)  # começa como lista
    for i in range(0, len(ciphertext_bytes), 16):
        bloco = list(ciphertext_bytes[i:i+16])
        estado = chave_para_estado(bloco)
        decriptado = estado_para_bytes(decrypt(estado, w))  # bytes
        xorado = xor_blocos(list(decriptado), anterior)     # lista XOR lista
        resultado += bytes(xorado)
        anterior = bloco  # próximo usa o cifrado atual — já é lista
    return resultado


#isso aq eu tive que implementar depois pra ter estado pra bytes e vice versa

def estado_para_bytes(estado): # ta isso aqui é meio chato mas da pra explicar
    #como eu tinha visto na aula com o prof, o aes trampa e cima de column major, nn row major 
    #jusatmente por isso a gegnte faz o inverso de primeiro vai na coluna toda e depois passa a row
    resultado = []
    for col in range(4):
        for row in range(4):
            resultado.append(estado[row][col])
    return bytes(resultado) #é trivial essa funcao mas sem ela n rola de fazer traducao ao vivo e acores

def bytes_p_lista(dados):
    return list(dados)




'''plaintext = [
    0x32, 0x43, 0xf6, 0xa8,
    0x88, 0x5a, 0x30, 0x8d,
    0x31, 0x31, 0x98, 0xa2,
    0xe0, 0x37, 0x07, 0x34
]'''  # ta detalhe importante nesse plaintext, isso aq era só um exemplo que eu pedi, e era na hora de testar as implementações. mas eu sinceramente nao terifa feito ele hj em dia
# mais porque querendo ou nao transformar uma senha em linguagem humana faz parte sim da implementacao, ent eu teria feito direto mas oh well

'''chave = [ #q eu tmbm vo trocar
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
]''' # pois bem mesmo conceito, mas agora a gente gera a chave no derivar chave, ent n faz mt sentido ter aqui



#chave padrao
def chave_para_estado(chave): #ta primeiro bagulho que eu entendi, esse key to state, na real pega um bloco matriz wtv, e deixa formato 
    # do jeito que a gente quer, no caso uma face de cubo magico praticamente se ele fosse 2d, entao por exemplo eu pego meu bloco chave,
    #e jogo ele aqui pra ele formatar, mesma coisa com minha round key
    estado = [[0] * 4 for _ in range(4)]
    # na pratica pensa o seguinte, isso aqui pega uma string de dados linear e transforma em uma 4x4, eu realmente preciso alterar os nomes delas pra ficarem mais genericos e entendiveis eu acho
    for i in range (16):
        row = i % 4
        col = i // 4
        estado[row][col] = chave[i]
    return estado

#passo 1 ADDROUNDKEY

def adicionar_roundkey(estado, roundkey):
    for i in range(4):
        for j in range(4):
            estado[i][j] ^= roundkey[i][j]
    return estado # essa funcao simplesmente aplica um xor em cima do do estado atual, o ^ é o operador pra isso sempre bom lembrar,

#for row in estado:
#    print([hex(x) for x in row])

#passo 2 state = a nossa grid de encriptacao, ou melhor o nosso cubo magico



#passo 3 SUB BYTES


def sub_bytes(estado):
    for i in range(4):
        for j in range(4):
                estado[i][j] = S_BOX[estado[i][j]]
    return estado # como da pra ver aqui é uma operação simples de subsituição pela lookup tabble, 

'''teste '''

# estado = sub_bytes(estado)
'''
for row in estado:
    print([hex(x) for x in row])
'''
#passo 4 SHIFTROWS

#corta o mais a esquerda, tapa na bunda e vai pra esquerda e fecho, isso tudo controlando pelo indice, a primeira n acontece nada, a segunda corta
# de ladinho, a terceira slice no meio e a quarta tu mete tapa no mais e esquerda e faz ele dar a volta ao mundo

def shift_rows(estado):
    for i in range(1, 4):
        estado[i] = estado[i][i:] + estado[i][:i]
    return estado

#o sgit rows é basicamente um slicer, vc só vai cortar a matriz e utilizando i vai cortar ela de formas diferentes nada de mais

# shift_rows(estado)
'''
for row in estado:
    print([hex(x) for x in row])
'''
#passo 5 MIXCOLUMNS

#cacete que inferno vo nem tentar comentar essa porra

# ah mas eu vo comentar essa porra

#ta eu puxei ate o nome do cara que ivento essa porra, pelo visto tudo se baseia em um frances chamado evariste galois, que foi um animal que morreu com 20 anos em um duelo
#sabe se deus pelo que, mas oq interessa é que ele antes de morrer desenvolveu a teoria que hoje em dia virou o gmul, teoria dos grupos e campos que exlica quando e porque sistemas
#matematicos funcionam de forma fechada e reversivel

'''campo no sentido matematico é um conjunto de numeros onde voce pode somar subtrair dividir e sempre ficar dentro do mesmo conjjunto, os racionais sao um campo os reais sao um campo, 
os inteiros nao mas inteiro é nuemro broxa logo fds, mas de forma geral eles funcionam assim

vai ter uma panelinha, não tem nenhuma combinação possivel dentro dessa penlinha que não fique de alguma forma dentro da mesma panela'''
"""e nesse caso o guml usa um negocio chamado  gf(2 na oitava),ou seja TODOS os valores possiveis de 1 byte, qualquer operacao feita com esse byte vai retornar algo no sentido de
256 possibilidades, de 0 a 255, q é 2 na oitava,MAS TEM UM DETALHEEEEEEEEEE

a multiplicacao aqui nao e normal, ela foi desenvolvida pra ficar necessariamente dentro de um campo."""

# ENTAO NA PRATICA, gmul é, multiplicar dois btes usando as regras do campo de galois, pra que o resultado seja sempre um byte valido e a operação seja sempre reversivel

def gmul(a, b): # aq na definicao a e b vao ser os dois bytes que a gente vai usar
    p = 0 #isso aqui é bem importante, P é o retorno da nossa operação, mas como ele vai sofrer os processos de xor ele começa em 0
    for _ in range(8): # b é um byte, logo tem 8 bits, a gente vai processar cada um desses bits separadamente do mais significativo pro mais significativo
        if b & 1: #isso aqui isola o bit menos siginificativo de b, pq & realiza uma comparação bit a bit, e nessa brincadeira se o bit for 1, sinifica que A contribui pro
            #resuktado nessa casa, logo a ggentre soma, que em gf2 é um xor
            p ^= a

        high_bit = a & 0x80 # aqui a gente isola o o bit mais significativo que é o 7, pois ele que define se a gente teve perda de informação ou não, ou melhor overflow
        #isso acontece porque se for 0, a gente ta de boa, se for 1, o numero mudou na hora de shiftar
        a <<= 1 #multiplica a por 2  e descloca todos os bits 1 vez pra esquerda

        if high_bit: # eis la queston, se o bit original do 7 (lembrandoq ue a gente comeca a contar no 0, era 1, entao a gente tem overflow e ele sai do campo de 256
            # logo a gente precisa corrigir isso, com uma reducao polinomial, que é um ngc q eu nn entend mt bem mas paciencia
            a ^= 0x1b # qq eu sei, isso aqui é um polinomio irredutivel, que a gente subtrai, mas lmebrando que aqui uma soma e subtracao sao ambas xor
        a &= 0xff # e isso aqui garante que a nunca pasa de 1 byte, o pyhton em si nao limita os inteiros logo o nosso a poderia crescer forever, e isso aqui só impede isso
        b >>= 1 # aq a ggente avanca pro proximo bit de b, e descarta o que a acabou de ser processado
    return p # e por fim a gente retorna o que a gente precisava no final de tudo

def mix_columns(estado): # o mix columns é provavelmnente a parada mais confusa aqui ESPECIALMENTE se voce nao entende como o ggmul funciona
    # mas sem ela aes ia ser quebrado de forma facil pra caralho, é o coração da parada mesmo, voce basicamente vai pegar todos os bytes de uma coluna, e derivar eles usando uma
    #tabela fixa, e com isso todos esse byte novo vai depender de todos os outros anteriores , ou seja se mudar 1 byte muda a saida inteira, e agente repete isso uma CARALEADA de vezesz
    # ate isso aqui ficar completamente irreconhecivel, ent imagina uma corrente enorme  onde cada elo depende do anterior, e se mudar qlqr coisinha, TUDO MUDA, basicamente isso

    # nao que eu entendaaaaaa mas eu to me virando, o que importa aq é, tem uma tabela fixa chamada rcon que é definida pela documentacao do aes em si
    for j in range(4):
        a0 = estado[0][j] # aqui a gente pega todos os valores da coluna 1 2 3 e 4
        a1 = estado[1][j]
        a2 = estado[2][j]
        a3 = estado[3][j]

        estado[0][j] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3 # todas essas operacoes sao definidas pela tabela do rcon, no sentido de ter varios valores pra multiplicar e somar
        estado[1][j] = a0 ^ gmul(a1, 2) ^ gmul(a2,3) ^ a3 # eles ficam soltos na tabela a principio, mas quando voce conecta com os valores do estado voce tem as propriedades
        estado[2][j] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3) # aq por exemplo vai ter tudo vezes 1 2 ou 3, e dai soma entre esses valores segundo a tabela
        estado[3][j] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2) # assim que a gegnte faz as colunas ficarem embaralhadas mas que ainda fiquem reversiveis de alguma forma
    return estado  # em sumo é isso tlgd, mas é bem dificil de aplicar 

'''teste'''

# estado = mix_columns(estado)
'''
for row in estado:
    print([hex(x) for x in row])
'''

#expansoes de chave

#6 keyexpansion ou keyschedule


def rot_excord(word):
    return word[1:] + word[:1]

def sub_word(word):
    return [S_BOX[b] for b in word]

'''def key_expansion(chave): #isso aq transforma a chave em words

    w = []

    for i in range(4):
        w.append(chave[4*i:4*(i+1)]) # aq sao as primeiras words, a chave original

    for i in range(4, 44):
        temp = w[i-1].copy()

        if i % 4 == 0 :
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] ^=  RCON[(i//4)-1]

        # agora vem o xor de palavra com palavra
        new_word = []
        for j in range(4):
            new_word.append(w[i-4][j] ^ temp[j])       
        w.append(new_word)
    return w 
'''
#pra gerar a round key, cada uma = 4 words 
 

# essa parte toda aqui vai ser a nossa expansão de chave, então vamo devagar firmeza
# o aes 256 tem 14 rodadas, cada rodada precisa de uma chave diferente de 16 bytes, e todas elas sao geradas a partir da chave original, entao fica 14 + 1 inicial

#outro detalhe, no aes tem o conceito de word, que na verdade são incriveis 4 bytes, e só, uma chave de 16 bytes tem 4 words, uma de 32 tem 8 words e por ai vai
# a gente trabalha dessa forma pq é mais facil trabalhar de 4 em 4 do que meter logo 32, lembrando q vc começa com uma chave de 32 bytes


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



'''
print("Round 0:")
for row in get_round_key(w, 0):
    print([hex(x) for x in row])

print("\nRound 1:")
for row in get_round_key(w, 1):
    print([hex(x) for x in row])
'''
#função de encriptacao e inverso

#7encrypt 

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


'''
for row in estado:
    print([hex(x) for x in row])

'''
#7 e decrypt
#seguido de
#invsubbytes
#invshiftrows
#invmixcolumns

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