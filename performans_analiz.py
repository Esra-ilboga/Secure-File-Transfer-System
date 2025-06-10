import subprocess
import platform
import re
from tabulate import tabulate

# iperf3.exe dosyasının bulunduğu tam yol
IPERF_PATH = r"C:\Users\ilbog\Downloads\iperf3.19_64\iperf3.19_64\iperf3.exe"

def ping(host="8.8.8.8", count=4):
    """Gerçekçi RTT için 8.8.8.8'e ping atar."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    result = subprocess.run(["ping", param, str(count), host], capture_output=True, text=True)
    return result.stdout

def iperf_test(host="127.0.0.1", protocol="TCP"):
    """iperf testi (localhost üzerinden)"""
    if protocol.upper() == "UDP":
        result = subprocess.run([IPERF_PATH, "-c", host, "-u", "-b", "10M"], capture_output=True, text=True)
    else:
        result = subprocess.run([IPERF_PATH, "-c", host], capture_output=True, text=True)
    return result.stdout

def analiz_et(ping_output, iperf_output, protokol):
    """Ping ve iperf çıktılarından analiz"""
    ping_lines = ping_output.strip().split("\n")
    iperf_lines = iperf_output.strip().split("\n")

    min_rtt = avg_rtt = max_rtt = "?"

    for line in ping_lines:
        if "Minimum" in line and "Maximum" in line and "Average" in line:
            values = re.findall(r'\d+', line)
            if len(values) >= 3:
                min_rtt, max_rtt, avg_rtt = values[0], values[1], values[2]
            break

    bandwidth = "?"
    for line in reversed(iperf_lines):
        if "receiver" in line.lower() and "bits/sec" in line:
            parts = line.strip().split()
            for i in range(len(parts) - 1):
                if "bits/sec" in parts[i + 1]:
                    bandwidth = parts[i] + " " + parts[i + 1]
                    break
            break

    return {
        "Protokol": protokol,
        "Min RTT (ms)": min_rtt,
        "Avg RTT (ms)": avg_rtt,
        "Max RTT (ms)": max_rtt,
        "Bant Genişliği": bandwidth
    }

def performans_raporu():
    print("🔧 Performans ölçümleri başlatıldı...\n")
    sonuçlar = []

    for protokol in ["UDP", "TCP"]:
        print(f"➤ {protokol} için ping testi (8.8.8.8)...")
        ping_out = ping("8.8.8.8")

        print(f"➤ {protokol} için iPerf testi (127.0.0.1)...")
        iperf_out = iperf_test("127.0.0.1", protokol)

        analiz = analiz_et(ping_out, iperf_out, protokol)
        sonuçlar.append(analiz)

    tablo = tabulate(sonuçlar, headers="keys", tablefmt="fancy_grid")
    print("\n📊 Performans Tablosu:")
    print(tablo)

    with open("performans_raporu.txt", "w", encoding="utf-8") as f:
        f.write(tablo + "\n")

if __name__ == "__main__":
    performans_raporu()
