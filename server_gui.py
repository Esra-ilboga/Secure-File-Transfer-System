import threading
import tkinter as tk
from tkinter import messagebox, ttk
import socket, pickle, os
from modules.crypto_tools import aes_decrypt, rsa_decrypt, load_private_key
from modules.network_utils import receive_packets, reassemble_data
from config import RSA_OZEL, AUTH_TOKEN, PORT, PORT_TCP

class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Gelişmiş Server GUI - TCP/UDP Destekli")
        self.token = tk.StringVar()
        self.protocol = tk.StringVar(value="UDP")
        self.simulate_loss = tk.BooleanVar(value=False)  # ✅ Simülasyon kontrolü
        self.status_label = None

        self.setup_gui()

    def setup_gui(self):
        notebook = ttk.Notebook(self.root)
        server_tab = ttk.Frame(notebook)
        notebook.add(server_tab, text="Sunucu")
        notebook.pack(expand=1, fill="both")

        tk.Label(server_tab, text="Doğrulama Token:").pack(pady=5)
        tk.Entry(server_tab, textvariable=self.token).pack(pady=5)

        tk.Label(server_tab, text="Protokol Seç:").pack(pady=5)
        ttk.Combobox(server_tab, values=["UDP", "TCP"], textvariable=self.protocol).pack()

        # ✅ Simülasyon Checkbutton'ı
        tk.Checkbutton(server_tab, text="Paket Kaybı Simülasyonu (%20)", variable=self.simulate_loss).pack(pady=5)

        tk.Button(server_tab, text="Dinlemeyi Başlat", command=self.baslat_server).pack(pady=10)
        self.status_label = tk.Label(server_tab, text="Durum: Beklemede", fg="blue")
        self.status_label.pack(pady=5)

    def baslat_server(self):
        if not self.token.get():
            messagebox.showerror("Eksik Token", "Lütfen önce bir token girin.")
            return

        if not os.path.exists("test_dosyasi"):
            os.makedirs("test_dosyasi")

        protokol = self.protocol.get()
        if protokol == "UDP":
            self.status_label.config(text="UDP dinleniyor...", fg="orange")
            try:
                # ✅ Simülasyon parametresi gönderildi
                packets = receive_packets(simulate_loss=self.simulate_loss.get(), loss_rate=0.2)
                data = reassemble_data(packets)
                if not data:
                    raise ValueError("UDP ile alınan veri eksik veya bozuk.")

                packet = pickle.loads(data)
                if packet.get("token") != self.token.get():
                    raise PermissionError("Token doğrulama başarısız.")

                private_key = load_private_key(RSA_OZEL)
                aes_key = rsa_decrypt(packet['aes_key'], private_key)
                plain = aes_decrypt(packet['nonce'], packet['data'], packet['tag'], aes_key)

                filename = packet.get("filename", "udp_dosya.txt")
                path = os.path.join("test_dosyasi", f"udp_{filename}")
                with open(path, "wb") as f:
                    f.write(plain)

                self.status_label.config(text=f"UDP Dosya çözüldü: {filename}", fg="green")
                messagebox.showinfo("Başarılı", f"UDP dosyası kaydedildi:\n{path}")
            except Exception as e:
                self.status_label.config(text="UDP Hata", fg="red")
                messagebox.showerror("Hata", str(e))

        elif protokol == "TCP":
            self.status_label.config(text="TCP dinleniyor...", fg="orange")
            threading.Thread(target=self.tcp_listen, daemon=True).start()

        else:
            self.status_label.config(text="Geçersiz protokol!", fg="red")

    def tcp_listen(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", PORT_TCP))
            s.listen(1)
            conn, addr = s.accept()

            data = b''
            while True:
                part = conn.recv(4096)
                if not part:
                    break
                data += part
            conn.close()

            if len(data) < 100:
                raise ValueError("TCP verisi eksik geldi.")

            packet = pickle.loads(data)
            if packet.get("token") != self.token.get():
                self.status_label.config(text="Token hatalı", fg="red")
                messagebox.showerror("Yetkisiz", "Token doğrulaması başarısız!")
                return

            private_key = load_private_key(RSA_OZEL)
            aes_key = rsa_decrypt(packet['aes_key'], private_key)
            plain = aes_decrypt(packet['nonce'], packet['data'], packet['tag'], aes_key)

            filename = packet.get("filename", "tcp_dosya.txt")
            path = os.path.join("test_dosyasi", f"tcp_{filename}")
            with open(path, "wb") as f:
                f.write(plain)

            self.status_label.config(text=f"TCP Dosya çözüldü: {filename}", fg="green")
            messagebox.showinfo("Başarılı", f"TCP dosyası kaydedildi:\n{path}")

        except Exception as e:
            self.status_label.config(text="TCP Hata", fg="red")
            messagebox.showerror("Hata", f"TCP işlem başarısız: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()
