import hashlib
import os
from aes256 import key_expansion_256, encrypt_cbc, decrypt_cbc, gerar_iv
 
COFRE = "cofre.txt"
 
 
def derivar_chave(senha, salt=None):
    '''
    Deriva uma chave AES-256 de 32 bytes a partir da senha mestre usando PBKDF2-HMAC-SHA256.
    Se salt não for informado, gera um novo aleatório de 16 bytes.
    '''
    if salt is None:
        salt = os.urandom(16)
    chave = hashlib.pbkdf2_hmac(
        'sha256',
        senha.encode(),
        salt,
        100000,
        dklen=32
    )
    return chave, salt
 
 
def adicionar_senha(senha_mestre):
    site  = input("Site: ")
    senha = input("Senha do site: ")
 
    tamanho = len(senha)
    tamanho_bytes = bytes([tamanho >> 8, tamanho & 0xFF])
 
    chave_bytes, salt = derivar_chave(senha_mestre)
    w  = key_expansion_256(list(chave_bytes))
    iv = gerar_iv()
 
    cifrado_bytes = encrypt_cbc(senha, w, iv)
 
    with open(COFRE, "a") as f:
        f.write(f"{site}|{salt.hex()}|{iv.hex()}|{cifrado_bytes.hex()}|{tamanho_bytes.hex()}\n")
 
    print(f"[+] '{site}' salvo.")
 
 
def abrir_cofre(senha_mestre):
    confirmacao = input("Confirme a senha mestre: ")
    if confirmacao != senha_mestre:
        print("[-] Senha incorreta.")
        return
 
    if not os.path.exists(COFRE):
        print("Cofre vazio.")
        return
 
    linhas = []
    with open(COFRE, "r") as f:
        for linha in f:
            site, salt_hex, iv_hex, cifrado_hex, tamanho_hex = linha.strip().split("|")
 
            salt          = bytes.fromhex(salt_hex)
            iv            = list(bytes.fromhex(iv_hex))
            cifrado_bytes = bytes.fromhex(cifrado_hex)
            tamanho_bytes = bytes.fromhex(tamanho_hex)
 
            tamanho_original = (tamanho_bytes[0] << 8) | tamanho_bytes[1]
 
            chave_bytes, _ = derivar_chave(senha_mestre, salt)
            w = key_expansion_256(list(chave_bytes))
 
            senha = decrypt_cbc(cifrado_bytes, w, iv)[:tamanho_original].decode()
            linhas.append(f"{site}: {senha}")
 
    with open("cofre_aberto.txt", "w") as f:
        f.write("\n".join(linhas))
 
    print("[+] cofre_aberto.txt gerado:")
    for l in linhas:
        print(" ", l)
 
 
if __name__ == "__main__":
    senha_mestre = input("Senha mestre: ")
 
    while True:
        opcao = input("\n1 - adicionar senha\n2 - abrir cofre\n0 - sair\n> ")
 
        if opcao == "1":
            adicionar_senha(senha_mestre)
        elif opcao == "2":
            abrir_cofre(senha_mestre)
        elif opcao == "0":
            break