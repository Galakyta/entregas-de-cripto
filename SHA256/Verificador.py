import os
import sys
from sha256 import sha256
ARQUIVO_HASHES = "hashes.txt"

def carregar_hashes():
    hashes = {}

    if not os.path.exists(ARQUIVO_HASHES):
        return hashes

    with open(ARQUIVO_HASHES, "r", encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()

            if "|" in linha:
                nome, h = linha.split("|", 1)
                hashes[nome] = h

    return hashes

def salvar_hash(nome_arquivo, h):
    hashes = carregar_hashes()

    hashes[nome_arquivo] = h

    with open(ARQUIVO_HASHES, "w", encoding="utf-8") as f:
        for nome, valor in hashes.items():
            f.write(f"{nome}|{valor}\n")

def hash_arquivo(caminho):
    with open(caminho, "rb") as f:
        conteudo = f.read()
    return sha256(conteudo)


def gerar(caminho):
    if not os.path.exists(caminho):
        print(f"xcaminho nn encontrado: {caminho}")
        return

    h = hash_arquivo(caminho)

    nome = os.path.basename(caminho)

    salvar_hash(nome, h)

    print(f"\nhashzinho salvo em {ARQUIVO_HASHES}")

    print(f"\narquivo: {caminho}")
    print(f"SHA256: {h}")
    print("\nguarde esse hash para verificação")


def verificar(caminho):
    nome = os.path.basename(caminho)

    hashes = carregar_hashes()

    if nome not in hashes:
        print("\nnn tem hash pra esse arquivo")
        return

    hash_salvo = hashes[nome]
    hash_atual = hash_arquivo(caminho)

    print(f"\nArquivo: {nome}")
    print(f"Hash salvo: {hash_salvo}")
    print(f"Hash atual: {hash_atual}")

    if hash_salvo == hash_atual:
        print("\noriginal o arquivo não foi alterado.")
    else:
        print("\noLIginal o arquivo foi alterado.")
if __name__ == "__main__":
    print("verificador de autenticidade com sha256")
    print("\n1- Gerar hash de um arquivo")
    print("2- Verificar autenticidade de um arquivo")
    opcao = input("\n> ").strip()

    if opcao == "1":
        caminho = input("Caminho do arquivo: ").strip()
        gerar(caminho)

    elif opcao == "2":
        caminho = input("Caminho do arquivo: ").strip()
        verificar(caminho)

    else:
        print("Opção inválida.")