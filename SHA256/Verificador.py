import os
import sys
from sha256 import sha256

def hash_arquivo(caminho):
    with open(caminho, "rb") as f:
        conteudo = f.read()
    return sha256(conteudo)


def gerar(caminho):
    if not os.path.exists(caminho):
        print(f"[-] Arquivo não encontrado: {caminho}")
        return

    h = hash_arquivo(caminho)
    print(f"\nArquivo : {caminho}")
    print(f"SHA-256 : {h}")
    print("\n[+] Guarde esse hash para verificar a autenticidade futuramente.")


def verificar(caminho, hash_fornecido):
    if not os.path.exists(caminho):
        print(f"[-] Arquivo não encontrado: {caminho}")
        return

    h_atual = hash_arquivo(caminho)

    print(f"\nArquivo        : {caminho}")
    print(f"Hash fornecido : {hash_fornecido}")
    print(f"Hash calculado : {h_atual}")

    if h_atual == hash_fornecido.strip().lower():
        print("\n[AUTENTICO] O arquivo não foi alterado.")
    else:
        print("\n[INVALIDO] O arquivo foi alterado ou o hash está incorreto.")


if __name__ == "__main__":
    print("=== Verificador de Autenticidade SHA-256 ===")
    print("\n1 - Gerar hash de um arquivo")
    print("2 - Verificar autenticidade de um arquivo")
    opcao = input("\n> ").strip()

    if opcao == "1":
        caminho = input("Caminho do arquivo: ").strip()
        gerar(caminho)

    elif opcao == "2":
        caminho = input("Caminho do arquivo: ").strip()
        hash_fornecido = input("Hash SHA-256 para comparar: ").strip()
        verificar(caminho, hash_fornecido)

    else:
        print("Opção inválida.")