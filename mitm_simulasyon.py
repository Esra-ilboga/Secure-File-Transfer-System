from scapy.all import *

def mitm_simulasyonu():
    print("Sahte paket gönderiliyor...")
    sahte_paket = IP(src="192.168.1.1", dst="127.0.0.1")/UDP(sport=1234, dport=5005)/Raw(load=b"MITM Attack")
    send(sahte_paket)