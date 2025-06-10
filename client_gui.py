import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import socket, pickle, os
from hashlib import sha256
from Crypto.Random import get_random_bytes
from modules.crypto_tools import aes_encrypt, rsa_encrypt, load_public_key
from config import IP, PORT, PORT_TCP, CHUNK, RSA_GENEL, AUTH_TOKEN, DEFAULT_PROTOCOL

class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Gelişmiş Client GUI - TCP/UDP")
        self.token = tk.StringVar(value=AUTH_TOKEN)
        self.protocol = tk.StringVar(value=DEFAULT_PROTOCOL)

        self.setup_gui()

    def setup_gui(self):
        notebook = ttk.Notebook(self.root)
        client_tab = ttk.Frame(notebook)
        notebook.add(client_tab, text="İstemci")
        notebook.pack(expand=1, fill="both")

        tk.Label(client_tab, text="Token:").pack(pady=5)
        tk.Entry(client_tab, textvariable=self.token).pack(pady=5)

        tk.Label(client_tab, text="Protokol Seç:").pack(pady=5)
        ttk.Combobox(client_tab, values=["UDP", "TCP"], textvariable=self.protocol).pack()

        tk.Button(client_tab, text="Dosya(lar) Seç ve Gönder", command=self.send_files).pack(pady=10)

        self.status_label = tk.Label(client_tab, text="Durum: Beklemede", fg="blue")
        self.status_label.pack(pady=5)

    def send_files(self):
        dosyalar = filedialog.askopenfilenames()
        if not dosyalar:
            return

        try:
            pub_key = load_public_key(RSA_GENEL)

            for dosya in dosyalar:
                with open(dosya, 'rb') as f:
                    data = f.read()

                aes_key = get_random_bytes(32)
                nonce, encrypted, tag = aes_encrypt(data, aes_key)
                encrypted_key = rsa_encrypt(aes_key, pub_key)

                packet = pickle.dumps({
                    'aes_key': encrypted_key,
                    'nonce': nonce,
                    'tag': tag,
                    'data': encrypted,
                    'token': self.token.get(),
                    'filename': os.path.basename(dosya)
                })

                if self.protocol.get() == "UDP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    for i in range(0, len(packet), CHUNK):
                        part = packet[i:i+CHUNK]
                        piece_packet = pickle.dumps({
                            "id": i // CHUNK,
                            "payload": part,
                            "checksum": sha256(part).hexdigest()
                        })
                        sock.sendto(piece_packet, (IP, PORT))
                    end_packet = pickle.dumps({"id": -1, "payload": b"", "checksum": ""})
                    sock.sendto(end_packet, (IP, PORT))

                elif self.protocol.get() == "TCP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((IP, PORT_TCP))
                    sock.sendall(packet)
                    sock.close()

                self.status_label.config(text=f"Gönderildi: {os.path.basename(dosya)}", fg="green")
                self.root.update()

            messagebox.showinfo("Başarılı", "Tüm dosyalar gönderildi.")
            self.root.destroy()

        except Exception as e:
            self.status_label.config(text="Gönderim Hatası", fg="red")
            messagebox.showerror("Hata", f"Gönderim başarısız: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()
