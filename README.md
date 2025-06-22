# 🔒 Modern Active Directory Security Analyzer
Modern, kapsamlı Active Directory güvenlik analizi ve raporlama aracı. PowerShell AD kontrollerini Python'a dönüştürür ve güzel HTML raporları oluşturur.

![image](https://github.com/user-attachments/assets/a4078aa7-356a-4c14-b233-7a691f467b9a)

![image](https://github.com/user-attachments/assets/ec3660cb-2ae2-4eb9-b589-edc08ae6c21b)

![image](https://github.com/user-attachments/assets/4868f6a2-40b3-4ebc-a80c-68fd51178f07)

![image](https://github.com/user-attachments/assets/6feac705-c98d-4abf-b221-20530b903525)

![image](https://github.com/user-attachments/assets/eae879c2-211e-462b-b5ba-1e23da8c7873)


## ✨ Özellikler

- 🎯 **Demo & Gerçek AD Desteği** - RSAT olmadan demo modda çalışır
- 📊 **İnteraktif Web Arayüzü** - Flask tabanlı modern dashboard
- 📈 **Tarihi Veri Takibi** - SQLite ile güvenlik trendleri
- 🎨 **Güzel HTML Raporları** - Plotly grafikleri ile görsel raporlar
- 📧 **Email Entegrasyonu** - Otomatik rapor gönderimi
- 🔄 **JSON Export** - Veri entegrasyonu için
- 🚀 **Thread-Safe** - Çoklu kullanıcı desteği

## 🚀 Hızlı Başlangıç

### Gereksinimler
```bash
pip install ldap3 jinja2 matplotlib seaborn pandas flask plotly
```

### Kurulum
```bash
git clone https://github.com/kullaniciadi/ad-security-analyzer.git
cd ad-security-analyzer
python ad_security_analyzerv.py --create-config
```

### Kullanım

**Web Arayüzü:**
```bash
python ad_security_analyzerv.py --web --port 5000
```
Tarayıcıda: `http://localhost:5000`

**Komut Satırı:**
```bash
# Güvenlik taraması
python ad_security_analyzerv.py --scan

# HTML raporu oluştur
python ad_security_analyzerv.py --scan --report

# Email gönder
python ad_security_analyzerv.py --scan --report --email admin@domain.com

# JSON export
python ad_security_analyzerv.py --scan --export json
```

## 🎯 Demo Modu

RSAT/AD PowerShell modülü yoksa otomatik demo modda çalışır. Gerçekçi örnek verilerle tüm özellikleri test edebilirsiniz.

**Gerçek AD için:**
```powershell
# RSAT kurulumu (Windows)
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

## 📊 Güvenlik Kontrolleri

- ✅ **AD Sağlığı** - Domain Controller sayısı, AD nesneleri
- 👥 **Kullanıcı Yönetimi** - Devre dışı hesaplar, yönetici hakları
- 🔐 **Şifre Politikaları** - Süresi dolmayan şifreler, politika ayarları
- 🎫 **Kerberos Güvenliği** - KRBTGT yaşı, duplicate SPN'ler
- 🌐 **Ağ Güvenliği** - SMB v1, Firewall ayarları
- 📝 **Audit & Logging** - Gelişmiş audit politikası
- 👑 **Grup Yönetimi** - Domain Admins, boş gruplar
- 🛡️ **Gelişmiş Güvenlik** - Protected Users grup kullanımı

## 🌐 Web Arayüzü

- **Dashboard** - Anlık durum ve tarama başlatma
- **Latest Report** - Son tarama sonuçları ve grafikler
- **Historical Data** - Zaman içindeki güvenlik trendleri
- **Export Options** - JSON ve PDF export

## 📧 Email Konfigürasyonu

`config.ini` dosyasını düzenleyin:
```ini
[email]
smtp_server = smtp.gmail.com
smtp_port = 587
username = your-email@domain.com
password = your-app-password
```

## 📸 Ekran Görüntüleri

### Dashboard
![image](https://github.com/user-attachments/assets/ecbd7fe7-3521-46cf-9c0e-151222749dd9)


### Security Report
![image](https://github.com/user-attachments/assets/95b5cfb6-fb46-4412-a98f-e52230853c2c)


### Historical Trends
![image](https://github.com/user-attachments/assets/cea9db16-df6c-49ac-84c3-57ea196921d0)


## 🔧 Konfigürasyon

```ini
[database]
path = ad_security_history.db

[logging]
level = INFO

[email]
smtp_server = smtp.gmail.com
smtp_port = 587
username = your-email@domain.com
password = your-app-password

[reporting]
auto_email = false
recipients = admin@domain.com,security@domain.com
```

## 🤝 Katkıda Bulunma

1. Fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit edin (`git commit -m 'Add amazing feature'`)
4. Push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

## 📄 Lisans

MIT License - Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 🆘 Destek

- **Issues:** [GitHub Issues](https://github.com/kullaniciadi/ad-security-analyzer/issues)
- **Discussions:** Sorularınız için GitHub Discussions kullanın

## 🏷️ Versiyon Geçmişi

- **v1.0.0** - İlk sürüm
  - Modern web arayüzü
  - Demo modu desteği
  - Kapsamlı güvenlik kontrolleri
  - Thread-safe veritabanı

---

⭐ **Beğendiyseniz yıldız atmayı unutmayın!**
Önder AKÖZ - https://ondernet.net
