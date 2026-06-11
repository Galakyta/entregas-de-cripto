import tkinter as tk
import urllib.request
import json

CENTRAL = "http://localhost:8000"

def buscar():
    with urllib.request.urlopen(
        CENTRAL + "/ultimo"
    ) as r:
        return json.loads(r.read())    
janela = tk.Tk()
janela.title("PATATONTO")
janela.geometry("700x500")

chat = tk.Text(janela)
chat.pack(fill="both", expand=True)

ultimo = None

def atualizar():
    global ultimo

    try:
        msg = buscar()

        if msg["chunks"]:

            atual = str(msg)

            if atual != ultimo:

                ultimo = atual

                chat.insert(
                    tk.END,
                    f"{msg['de']} -> {msg['para']}\n"
                )

                for chunk in msg["chunks"]:
                    chat.insert(
                        tk.END,
                        str(chunk) + "\n"
                    )

                chat.insert(
                    tk.END,
                    "\n-----------------\n\n"
                )

                chat.see(tk.END)

    except Exception as e:
        print("erro:", e)

    janela.after(1000, atualizar)

atualizar()
janela.mainloop()
