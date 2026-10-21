# IP Tarayıcı

Windows ve macOS için basit, GUI'li IP tarayıcı. Python 3 + tkinter, ek paket gerekmez.

## Özellikler
- Aralık girişi: `192.168.1.1-192.168.1.254`, `192.168.1.1-254`, `192.168.1.0/24`, birden fazla aralık virgülle
- Sonuç listesi: IP, durum, ping (ms), **cihaz adı**, MAC
- Cihaz adı sırayla ters DNS, NetBIOS (Windows PC'ler) ve mDNS/Bonjour (Mac, iPhone, yazıcı vb.) ile bulunur
- **Derin tarama:** ping'e cevap vermeyen cihazları da bulur (yaygın portlara bağlanma, NetBIOS ve ARP tablosu); açık servisleri (SMB, RDP, SSH, HTTP, yazıcı vb.) listeler
- Thread sayısı ve zaman aşımı ayarı, durdurma, CSV'ye aktarma, IP kopyalama

## Çalıştırma
```
python ip_scanner.py      # Windows
python3 ip_scanner.py     # macOS
```

## Tek dosyalık uygulama (.exe / .app)
- Windows: `build_windows.bat`
- macOS: `bash build_mac.sh`
- Ya da GitHub'da **Actions → Build → Run workflow**; derlenen dosyalar "Artifacts" bölümünden iner.

## Notlar
- Derin tarama kapalıysa ping'e cevap vermeyen cihaz listede görünmez. Derin tarama daha yavaştır (254 IP için yaklaşık 10-30 sn).
- ARP ile bulma yalnızca aynı ağ segmentindeki (aynı alt ağ) cihazlar için çalışır.
- Cihaz adı, cihaz bu protokollerden birine cevap vermiyorsa boş kalabilir.
