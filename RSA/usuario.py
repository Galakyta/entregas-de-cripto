# uso: python usuario.py patata 8001
# uso: python usuario.py patati 8002
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, sys, os, urllib.request, threading
import tkinter as tk
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from RSA_puro import keygen, encrypt_text, decrypt_text
gui = None
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
            gui.janela.after(
    0,
    lambda: gui.adicionar_mensagem(
        f"{de}: {texto}"
    )
)
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

threading.Thread(target=lambda: HTTPServer(("", PORTA), WebhookHandler).serve_forever(),
                 daemon=True).start()

# --- menu ---
# ---------------- GUI ----------------

class ChatGUI:
    def __init__(self):
        self.janela = tk.Tk()
        self.janela.title(f"ZipZop - {NOME}")
        self.janela.geometry("500x600")

        titulo = tk.Label(
            self.janela,
            text=f"{NOME} conversando com {OUTRO}",
            font=("Arial", 12, "bold")
        )
        titulo.pack(pady=5)

        self.chat = tk.Text(
            self.janela,
            state="disabled",
            wrap="word"
        )

        self.chat.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        frame = tk.Frame(self.janela)
        frame.pack(fill="x", padx=10, pady=10)

        self.entrada = tk.Entry(frame)
        self.entrada.pack(
            side="left",
            fill="x",
            expand=True
        )

        self.entrada.bind("<Return>", lambda e: self.enviar())

        botao = tk.Button(
            frame,
            text="Enviar",
            command=self.enviar
        )

        botao.pack(side="right", padx=5)

    def adicionar_mensagem(self, texto):
        self.chat.config(state="normal")
        self.chat.insert(tk.END, texto + "\n")
        self.chat.see(tk.END)
        self.chat.config(state="disabled")

    def enviar(self):
        texto = self.entrada.get().strip()

        if not texto:
            return

        try:
            pub_outro = buscar_pub(OUTRO)

            chunks = encrypt_text(
                texto,
                pub_outro
            )

            resp = post_central(
                "/enviar",
                {
                    "de": NOME,
                    "para": OUTRO,
                    "chunks": chunks
                }
            )

            if resp.get("ok"):
                self.adicionar_mensagem(
                    f"Você: {texto}"
                )

                self.entrada.delete(0, tk.END)

        except Exception as e:
            self.adicionar_mensagem(
                f"[ERRO] {e}"
            )

    def iniciar(self):
        self.janela.mainloop()
gui = ChatGUI()



gui.iniciar()

#ordem de execucao
#precisa abrir um terminal pra cada um, é só abrir uns 4 open in integrated terminal pra facilitar
#python server.py
#python usuario.py patata 8001
#python usuario.py patati 8002
#python patatonto.py