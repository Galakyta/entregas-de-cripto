import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))) # eu coloquyei isso aq pq tava dando conflito com alguma outra coisa que eu fiz(eu acho)
#na hora de puxar o import, e teoricamente isso faz que primeiro o programa puxe o que ta na pasta do propio script, mas nao sei como funciona

from RSA_puro import keygen, encrypt_text, decrypt_text

#gerando as chaves pra cada usuario

print("tentando gerar as lhaves")
pub_patata, priv_patata = keygen(512)
pub_patati, priv_patati = keygen(512)
print("lhaves generadas manito")

ultima_mensagem_cifrada = None  # chunks cifrados
ultimo_remetente = None

def enviar(texto, pub_destino): # funcao simples de receber e enviar meio trivial
    return encrypt_text(texto, pub_destino) # mas eu ja chamo o encrypt text aqui pra nao ter como falhar ou algum dado vazar

def receber(chunks, priv, pub):
    return decrypt_text(chunks, priv, pub)

def tela_usuario(nome, pub_proprio, priv_proprio, pub_outro, nome_outro):
    global ultima_mensagem_cifrada, ultimo_remetente # eu n queria ter feito com global mas pra fins de demonstracao achei que ficou coerente
    while True:
        print(f"\n------------- usuario = {nome} ------------- ")
        print(f" 1 = enviar mensagem p/ {nome_outro}")
        print(f" 2-  ver mensagens na inbox")
        print(f" 3- voltar")
        op = input(">> ").strip()

        if op == "1":
            texto = input(f"msg pra {nome_outro}: ").strip()
            if not texto:
                continue
            ultima_mensagem_cifrada = enviar(texto, pub_outro)
            ultimo_remetente = nome
            print(f"enviado ta la ja")

        elif op == "2":
            if ultima_mensagem_cifrada is None or ultimo_remetente == nome:
                print("0 notificacoes")
            else:
                msg = receber(ultima_mensagem_cifrada, priv_proprio, pub_proprio)
                print(f"\n  {ultimo_remetente}: {msg}")

        elif op == "0":
            break

def tela_patatonto():
    if ultima_mensagem_cifrada is None:
        print("\n nada pra ver aq")
        return
    print(f"\n PATATONTO (ultima mensagem de {ultimo_remetente})")
    print("chunks cifrados:")
    for i, chunk in enumerate(ultima_mensagem_cifrada):
        # mostra so os primeiros 60 chars do numero pra nao explodir o terminal mas poderia ser mt mais
        s = str(chunk)
        print(f"  [{i}] {s[:60]}{'...' if len(s) > 60 else ''}")

def menu():
    while True:
        print("\n--------------- zap do circo ---------------")
        print("1-Patata")
        print("2-Patati")
        print("3-Patatonto")
        print("0 - deu por hj")
        op = input(">> ").strip()

        if op == "1":
            tela_usuario("Patata", pub_patata, priv_patata, pub_patati, "Patati")
        elif op == "2":
            tela_usuario("Patati", pub_patati, priv_patati, pub_patata, "Patata")
        elif op == "3":
            tela_patatonto()
        elif op == "0":
            print("aurrevouir")
            break

menu()