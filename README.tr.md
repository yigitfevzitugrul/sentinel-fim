# Sentinel FIM

[English](README.md) | **Türkçe**

Linux ve Windows için bir dosya bütünlüğü izleme aracı. Bir dizin ağacının
güvenilir bir **referans durumunu (baseline)** kaydeder: her dosyanın SHA-256
özeti, dizinler, sembolik bağlantılar ve özel dosyalar. Daha sonra o andan
bu yana neyin **eklendiğini, silindiğini, değiştiğini veya türünün
değiştiğini** raporlar.

## Kurulum

```sh
cargo install --path .        # veya GitHub Releases'tan hazır binary indirin
```

Rust 1.88 veya üstü gerekir.

## Kullanım

```sh
sentinel-fim init /srv/data -b baseline.json --exclude '*.log'
sentinel-fim scan -b baseline.json                 # insan okunur rapor
sentinel-fim scan -b baseline.json --format json --report scan.json
sentinel-fim watch -b baseline.json                # gerçek zamanlı + periyodik tam tarama
sentinel-fim report scan.json                      # kaydedilmiş raporu yeniden göster
```

| Komut | Açıklama |
|---|---|
| `init` | Dizini tarar ve yeni bir baseline oluşturur |
| `scan` | Dizini yeniden tarar, baseline ile karşılaştırır |
| `verify` | Baseline dosyasının sağlamasını ve imzasını kontrol eder (dosya sistemini taramaz) |
| `report` | `scan --report` ile kaydedilmiş JSON raporu gösterir |
| `watch` | Dizini gerçek zamanlı izler, periyodik tam taramalarla uzlaştırır |
| `keygen` | Baseline imzalamak için Ed25519 anahtar çifti üretir |
| `sign` | Mevcut bir baseline dosyasını imzalar |

İmzalı baseline (gizli anahtarı izlenen makinede **tutmayın**):

```sh
sentinel-fim keygen --secret-key fim.secret --public-key fim.pub
sentinel-fim sign -b baseline.json --secret-key fim.secret
sentinel-fim scan -b baseline.json --public-key fim.pub --require-signature
```

İsteğe bağlı TOML yapılandırması `--config DOSYA` ile verilir; çalışma
dizininde otomatik olarak aranmaz. Komut satırı seçenekleri önceliklidir,
hariç tutma listeleri birleştirilir, göreli yollar yapılandırma dosyasının
bulunduğu dizine göre çözülür:

```toml
root = "/srv/data"
baseline = "/var/lib/sentinel-fim/baseline.json"
public_key = "/etc/sentinel-fim/baseline.pub"
require_signature = true
exclude = ["*.tmp", "/cache"]   # '/' yoksa: her derinlikteki ad; '/' varsa: kökten yol
follow_symlinks = false
one_file_system = true
max_file_size = 1073741824

[watch]
debounce_ms = 500
rescan_interval_secs = 3600     # 0 periyodik tam taramayı kapatır
```

Loglar stderr'e yazılır (`-v`, `-vv`, `-q` veya `SENTINEL_FIM_LOG=debug`);
raporlar stdout'a yazılır, böylece JSON çıktısı loglarla karışmaz.

## Çıkış kodları

| Kod | Anlamı |
|---|---|
| 0 | temiz / baseline geçerli |
| 1 | değişiklik tespit edildi |
| 2 | kullanım hatası |
| 3 | çalışma hatası veya eksik tarama (bazı girdiler kontrol edilemedi) |
| 4 | baseline reddedildi (bozuk, düzenlenmiş, hatalı imza) |

## Güvenlik modeli (özet)

- Sembolik bağlantılar ve Windows junction'ları varsayılan olarak **takip
  edilmez, kaydedilir**. Dosyalar `O_NOFOLLOW|O_NONBLOCK` (Unix) veya
  `FILE_FLAG_OPEN_REPARSE_POINT` (Windows) ile açılır ve açılan tanıtıcı
  yeniden kontrol edilir; böylece listeleme ile açma arasında dosyanın
  değiştirilmesi tespit edilir.
- Okunurken değişen dosyalar, okunamayan dosyalar ve dizinler raporlanır
  (çıkış kodu 3); içerikleri "silindi" değil, *doğrulanamadı* olarak gösterilir.
- Baseline sağlaması yalnızca bozulmayı tespit eder. Kasıtlı değiştirmeyi
  yalnızca operatörün verdiği açık anahtarla doğrulanan bir **imza** tespit eder.
- Gerçek zamanlı olaylar yalnızca ipucudur: her olay ilgili yolun yeniden
  taranmasını tetikler; olay kaybı, kuyruk taşması ve periyodik zamanlayıcı
  tam taramayı tetikler.
- Sınırlamalar: yalnızca içerik özeti alınır (izinler, ACL, xattr ve Windows
  ADS kapsam dışıdır); zaman damgası çözünürlüğü; root/yönetici yetkisine
  sahip bir saldırgan aracın kendisini devre dışı bırakabilir.

Ayrıntılar (İngilizce): [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md),
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (dosya biçimleri ve tasarım kararları).

## Performans (ölçülmüş, release build, sıcak önbellek)

100 000 × 1 KiB dosya + bir adet 1 GiB dosya:

| Platform | `init` | `scan` |
|---|---|---|
| Linux (Docker) | 1,5 s, en fazla 53 MiB | 1,6 s, en fazla 43 MiB |
| Windows 11 | 8,5 s, en fazla 73 MiB | 8,6 s, en fazla 47 MiB |

SHA-256 ≈ 1,44 GiB/s; tek iş parçacıklı BLAKE3 yalnızca ~%18 daha hızlıydı,
bu yüzden SHA-256 kullanılmaya devam ediyor. Ölçümleri
`scripts/perf_large_tree.py` ve `cargo bench` ile tekrarlayabilirsiniz.

## Geliştirme

```sh
cargo test                       # Windows/Linux üzerinde
.\scripts\test-linux.ps1         # Docker'da, root olmayan kullanıcıyla Linux testleri
```

Lisans: MIT OR Apache-2.0.
