from http.server import HTTPServer, BaseHTTPRequestHandler
import json, sys, os, urllib.request, threading

print("Servidor central iniciando...\n")

# servidor nao gera nem guarda chaves privadas
# so conhece as chaves publicas que os clientes registram
USERS  = {}  # { nome: { "pub": (e, n), "webhook": url } }
ultimo = {"de": None, "para": None, "chunks": []}

def disparar_webhook(url, payload):
    def _send():
        try:
            data = json.dumps(payload).encode()
            req  = urllib.request.Request(url, data=data,
                                           headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            print(f"  [webhook falhou pra {url}: {e}]")
    threading.Thread(target=_send, daemon=True).start()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n)) if n else {}

    def do_GET(self):
        parts = self.path.strip("/").split("/")

        # GET /chave/patati — devolve chave publica
        if parts[0] == "chave" and len(parts) == 2:
            u = parts[1]
            if u not in USERS:
                return self.send_json(404, {"erro": "usuario nao registrado"})
            e, n = USERS[u]["pub"]
            return self.send_json(200, {"e": e, "n": n})

        # GET /ultimo — patatonto
        if parts[0] == "ultimo":
            return self.send_json(200, ultimo)

        self.send_json(404, {"erro": "rota nao existe"})

    def do_POST(self):
        parts = self.path.strip("/").split("/")

        # POST /registrar  { "nome": "patata", "e": ..., "n": ..., "webhook": "http://..." }
        if parts[0] == "registrar":
            data = self.read_body()
            nome = data.get("nome")
            if not nome:
                return self.send_json(400, {"erro": "nome obrigatorio"})
            USERS[nome] = {
                "pub":     (data["e"], data["n"]),
                "webhook": data["webhook"],
            }
            print(f"  [{nome}] registrado (webhook: {data['webhook']})")
            return self.send_json(200, {"ok": True})

        # POST /enviar  { "de": "patata", "para": "patati", "chunks": [...] }
        # chunks ja chegam cifrados — servidor nao sabe o conteudo
        if parts[0] == "enviar":
            data   = self.read_body()
            de     = data.get("de")
            para   = data.get("para")
            chunks = data.get("chunks", [])

            if de not in USERS or para not in USERS:
                return self.send_json(400, {"erro": "usuario nao registrado"})
            if not chunks:
                return self.send_json(400, {"erro": "mensagem vazia"})

            ultimo.update({"de": de, "para": para, "chunks": chunks})
            print(f"  [{de} → {para}] {len(chunks)} chunk(s) — repassando webhook...")
            disparar_webhook(USERS[para]["webhook"], {"de": de, "chunks": chunks})
            return self.send_json(200, {"ok": True})

        self.send_json(404, {"erro": "rota nao existe"})

if __name__ == "__main__":
    port = 8000
    print(f"servidor central em http://localhost:{port}")
    print("rotas:")
    print("  POST /registrar  {nome, e, n, webhook}")
    print("  POST /enviar     {de, para, chunks}")
    print("  GET  /chave/<usuario>")
    print("  GET  /ultimo\n")
    HTTPServer(("", port), Handler).serve_forever()

#ordem de execucao
#precisa abrir um terminal pra cada um, é só abrir uns 4 open in integrated terminal pra facilitar
#python server.py
#python usuario.py patata 8001
#python usuario.py patati 8002
#python patatonto.py