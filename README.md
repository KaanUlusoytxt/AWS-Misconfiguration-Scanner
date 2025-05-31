# AWS Misconfiguration Scanner

Bu proje, AWS ortamındaki yaygın yanlış yapılandırmaları (misconfiguration) tespit etmek için geliştirilmiş bir tarayıcıdır.

## Özellikler
- IAM izinlerini analiz eder
- Güvenlik gruplarını kontrol eder
- S3 bucket erişimlerini inceler
- Hızlı raporlama ve çıktı desteği

## Gereksinimler
- Python 3.x
- boto3

## Kurulum
```bash
git clone https://github.com/KaanUlusoytxt/AWS-Misconfiguration-Scanner.git
cd AWS-Misconfiguration-Scanner
pip install -r requirements.txt
