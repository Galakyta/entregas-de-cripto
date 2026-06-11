# uso: python usuario.py patata 8001
# uso: python usuario.py patati 8002
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, sys, os, urllib.request, threading
import tkinter as tk
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from RSA_puro import keygen, encrypt_text, decrypt_text

NOME    = sys.argv[1] if len(sys.argv) > 1 else "patata"
PORTA   = int(sys.argv[2]) if len(sys.argv) > 2 else 8001
OUTRO   = "patati" if NOME == "patata" else "patata"
CENTRAL = "http://localhost:8000"

print(f"Gerando chaves para {NOME}... ", end="", flush=True)
pub, priv = keygen(512)
print("pronto.")

def post_central(path, body):
    data = json.dumps(body).encode()
    req  = urllib.request.Request(CENTRAL + path, data=data,
                                   headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

def get_central(path):
    with urllib.request.urlopen(CENTRAL + path) as r:
        return json.loads(r.read())

def buscar_pub(usuario):
    resp = get_central(f"/chave/{usuario}")
    return (resp["e"], resp["n"])

# registra no servidor: envia pub e endereco do webhook
e, n = pub
post_central("/registrar", {
    "nome":    NOME,
    "e":       e,
    "n":       n,
    "webhook": f"http://localhost:{PORTA}/mensagem",
})
print(f"registrado no servidor central.")
print(f"webhook em http://localhost:{PORTA}/mensagem\n")

# --- servidor webhook do cliente ---
class WebhookHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_POST(self):
        if self.path == "/mensagem":
            n_bytes = int(self.headers.get("Content-Length", 0))
            data    = json.loads(self.rfile.read(n_bytes))
            de      = data["de"]
            chunks  = data["chunks"]
            texto   = decrypt_text(chunks, priv, pub)  # decifra com chave privada local
            print(f"\n  🔔 {de}: {texto}")
            print(f">> ", end="", flush=True)
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

threading.Thread(target=lambda: HTTPServer(("", PORTA), WebhookHandler).serve_forever(),
                 daemon=True).start()

# --- menu ---
def menu():
    while True:
        print(f"=== {NOME} ===")
        print(f"  1. Enviar mensagem pra {OUTRO}")
        print(f"  2. Patatonto (ver ultimo cifrado)")
        print(f"  0. Sair")
        op = input(">> ").strip()

        if op == "1":
            texto = input("Mensagem: ").strip()
            if not texto:
                continue
            pub_outro = buscar_pub(OUTRO)          # busca pub do destinatario no servidor
            chunks    = encrypt_text(texto, pub_outro)  # cifra LOCALMENTE
            resp = post_central("/enviar", {"de": NOME, "para": OUTRO, "chunks": chunks})
            print("[enviado]\n" if resp.get("ok") else f"[erro: {resp}]\n")

        elif op == "2":
            resp = get_central("/ultimo")
            if not resp.get("chunks"):
                print("\n[nenhuma mensagem enviada ainda]\n")
            else:
                print(f"\n=== PATATONTO (de {resp['de']} pra {resp['para']}) ===")
                for i, chunk in enumerate(resp["chunks"]):
                    s = str(chunk)
                    print(f"  [{i}] {s[:60]}{'...' if len(s) > 60 else ''}")
                print()

        elif op == "0":
            print("tchau")
            break

menu()
