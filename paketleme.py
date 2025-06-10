from scapy.all import IP, send, Raw

def gonder_ozel_paket(data):
    ip_katmani = IP(dst="127.0.0.1", ttl=64, flags=2)  # DF bayrağı
    paket = ip_katmani / Raw(load=data)
    send(paket)
    