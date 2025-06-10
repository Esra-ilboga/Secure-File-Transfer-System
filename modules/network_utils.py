import socket
import pickle
import random
from hashlib import sha256
from config import PORT, CHUNK

def receive_packets(timeout=8, simulate_loss=False, loss_rate=0.2):
    """
    UDP üzerinden parça parça gelen verileri alır. 
    simulate_loss=True olursa, verilen oran kadar paket atlanır.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))
    sock.settimeout(timeout)
    received_chunks = {}
    print(f"[UDP] Dinleme başladı... Simülasyon: {'AÇIK' if simulate_loss else 'KAPALI'}")

    while True:
        try:
            data, _ = sock.recvfrom(CHUNK + 512)
        except socket.timeout:
            print("[UDP] Zaman aşımı.")
            break

        if not data:
            continue

        try:
            piece = pickle.loads(data)
        except:
            continue

        if piece.get("id") == -1:
            print("[UDP] Son paket alındı.")
            break

        # ✅ Paket kaybı simülasyonu
        if simulate_loss and random.random() < loss_rate:
            print(f"[Simülasyon] Paket {piece.get('id')} atlandı (kayıp).")
            continue

        payload = piece.get("payload")
        checksum = piece.get("checksum")

        if payload and checksum and sha256(payload).hexdigest() == checksum:
            received_chunks[piece["id"]] = payload
        else:
            print(f"[Hata] Paket {piece.get('id')} bozuk ya da eksik atlandı.")

    return received_chunks

def reassemble_data(chunks):
    """
    Parçaları sıralı şekilde birleştirir.
    Eksik parça varsa çözümleme yapılmaz.
    """
    if not chunks:
        return b''

    max_id = max(chunks)
    missing = [i for i in range(max_id + 1) if i not in chunks]
    if missing:
        print(f"[Uyarı] Eksik parçalar: {missing}")
        return b''  # eksikse çözülmesin

    return b''.join(chunks[i] for i in range(max_id + 1))
