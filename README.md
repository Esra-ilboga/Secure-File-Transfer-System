# 🔐 Advanced Secure File Transfer System with Low-Level IP Processing & Network Performance Analysis

## 📌 Amaç

Bu proje, güvenli dosya aktarımını hem TCP hem de UDP üzerinden gerçekleştiren, ağ katmanında IP manipülasyonu, saldırı simülasyonu ve performans analizini içeren gelişmiş bir sistem sunar. AES-256 ile şifreleme, RSA-2048 ile anahtar koruma, SHA-256 ile bütünlük kontrolü sağlanmıştır.

## 🧱 Sistem Mimarisi

| Bileşen            | Açıklama                                                   |
|--------------------|------------------------------------------------------------|
| **Client (İstemci)**     | Dosya seçimi, şifreleme ve gönderme                      |
| **Server (Sunucu)**      | TCP/UDP'ye göre dinleme, şifre çözme ve kaydetme         |
| **GUI**             | Protokol ve token seçimi, simülasyon kontrolü             |
| **Şifreleme**        | AES-256 (EAX) + RSA-2048                                   |
| **Performans Ölçüm** | `ping`, `iperf3`, `tabulate` ile ölçüm ve analiz           |
| **Simülasyon**       | Paket kaybı (%20) & MITM (spoofing)                        |

## ⚙️ Temel Özellikler

- ✅ **AES-256 + RSA-2048** ile şifreli dosya aktarımı  
- ✅ **SHA-256** ile parça bütünlüğü kontrolü  
- ✅ **Token** ile kimlik doğrulama  
- ✅ **UDP & TCP** desteği, GUI üzerinden seçim  
- ✅ **Paket kaybı simülasyonu** (`Clumsy` aracı & kod ile)  
- ✅ **MITM saldırı simülasyonu** (Scapy ile spoof edilmiş paket)  
- ✅ **Performans analiz aracı** (`iperf3`, `ping`, `tabulate`)  
- ✅ **Wireshark desteği** ile paket inceleme  

## 🖥️ Arayüzler (GUI)

### 🔹 Sunucu GUI
Sunucu tarafında oluşturulan grafiksel kullanıcı arayüzü (GUI), kullanıcı dostu bir deneyim sunarak aşağıdaki işlevleri yerine getirir:

- **Token Doğrulama**  
  İstemciden gelen token değeri, GUI üzerinden girilen doğrulama anahtarı ile karşılaştırılır. Eşleşme sağlanmazsa dosya çözülmez.

- **Protokol Seçimi (TCP / UDP)**  
  Kullanıcı, veri aktarımında hangi protokolün (TCP veya UDP) kullanılacağını GUI üzerinden seçebilir.

- **UDP için Paket Kaybı Simülasyonu**  
  GUI’de yer alan bir seçenekle %20 oranında rastgele paket kaybı simülasyonu aktif edilebilir (yalnızca UDP için geçerlidir).

- **Dinlemeyi Başlat**  
  Girilen token ve seçilen protokol doğrultusunda sunucu, dosya transferi için dinlemeye başlar.

- **Durum Göstergesi**  
  GUI üzerinden "Beklemede", "Dinleniyor", "Dosya çözüldü", "Token hatalı" gibi anlık durumlar kullanıcıya bildirilir.

#### 📸 Arayüz Görseli

![Sunucu Arayüzü](https://github.com/user-attachments/assets/87770241-596f-4bae-80fb-d81d35d2d8bf)

### 🔹 İstemci GUI

İstemci (Client) arayüzü, kullanıcıların dosya(ları) güvenli bir şekilde gönderebilmesi için tasarlanmıştır. Gelişmiş GUI sayesinde aşağıdaki özellikler sunulmaktadır:

- **Token Girişi**: Sunucu tarafında doğrulama yapılabilmesi için token değeri girilmelidir.
- **Protokol Seçimi**: Kullanıcı UDP veya TCP protokolünü seçerek dosya gönderimini başlatabilir.
- **Dosya Seçimi ve Gönderme**: Tekli veya çoklu dosya seçimi yapılabilir. Seçilen dosyalar AES-256 ile şifrelenerek gönderilir.
- **Durum Göstergesi**: Her bir dosyanın başarıyla gönderilme durumu GUI üzerinden izlenebilir.

#### 📸 Arayüz Görseli:
![İstemci Arayüzü](https://github.com/user-attachments/assets/e91d0f64-9577-4d86-b457-6c2469811196)


## 🛰️ IP Katmanı Manipülasyonu

- `Scapy` kullanılarak özel IP paketleri oluşturulmuştur:
  - TTL = 64
  - DF (Don’t Fragment) bayrağı
  - `Raw` bölümünde ASCII payload
  - Sahte kaynak IP (`spoofing`)

## 🕵️ MITM Saldırısı (Simülasyon)

- Sahte UDP paket, kaynak IP spoofing ile `127.0.0.1`'e gönderildi.
- Payload: `MITM Attack`
- Wireshark ile analiz edilerek kaynağın sahte olduğu doğrulandı.

![image](https://github.com/user-attachments/assets/9a93d54c-b0d5-40da-b951-2b2e1fb95985)


## 💥 Paket Kaybı Simülasyonu

| Yöntem        | Açıklama                                                                 |
|---------------|--------------------------------------------------------------------------|
| Kod ile       | `receive_packets(simulate_loss=True)` çağrısı ile %20 rastgele paket kaybı |
| Clumsy aracı  | GUI üzerinden UDP portuna gelen trafiğe %20 drop uygulaması yapılır     |

## 📈 Performans Analizi

- `ping 8.8.8.8` ile RTT ölçümü
- `iperf3 -c 127.0.0.1` ile bant genişliği ölçümü
- `tabulate` ile tablo oluşturulup `performans_raporu.txt` dosyasına yazılır

### Örnek Tablo:
![image](https://github.com/user-attachments/assets/a871d8c8-4780-4758-a3e4-179fe68ca421)


## ⚠️ Eksikler ve Geliştirme Alanları

- [ ] TCP'de çoklu dosya aktarımı yetersiz (tek bağlantıda bir dosya)
- [ ] UDP tarafında çoklu dosya hatalı davranıyor
- [ ] Paket sıralaması eksik, kayıplar tekrar gönderilemiyor (UDP)
- [ ] Dosya türü kontrolü yapılmıyor, MIME tespiti yok
- [ ] Performans testleri gerçek ağ ortamında yapılmadı
- [ ] Loglama eksik (hata günlükleme yok)
- [ ] RSA anahtarları sabit, oturum tabanlı değil
- [ ] MITM simülasyonu daha gelişmiş hale getirilebilir
- [ ] Sadece masaüstü GUI var, web/mobil desteklenmiyor

## 🧪 Test Ortamı

- Python 3.13.0
- Scapy
- PyCryptodome
- Tabulate
- iPerf3
- Wireshark
- Clumsy

## 🔗 Kaynaklar

- [Python Docs](https://docs.python.org/3/)
- [Scapy – Packet Manipulation Tool](https://scapy.net)
- [iPerf3 – Network Bandwidth Tool](https://github.com/esnet/iperf)
- [Clumsy – Network Simulator](https://jagt.github.io/clumsy/)
- [Wireshark](https://www.wireshark.org/)
- [Tabulate](https://pypi.org/project/tabulate/)
- [GeeksforGeeks](https://www.geeksforgeeks.org)


