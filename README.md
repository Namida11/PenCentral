# PenCentral

Öz pentest işini **bir mərkəzdən** idarə etmək üçün yüngül orchestrator.

Alətləri özü icad etmir. Sistemində quraşdırılmış mövcud CLI alətlərini zəncirləyir:

1. Subdomain enum — `subfinder` (+ istəsən `assetfinder`)
2. Live host / HTTP probe — `httpx`
3. Port scan — `naabu` və ya `nmap`
4. Directory enum — `ffuf` və ya `feroxbuster`
5. Template scan — `nuclei`

Repo: https://github.com/Namida11/PenCentral

```bash
git clone https://github.com/Namida11/PenCentral.git
cd PenCentral
python3 webapp.py
```

Yeniləmə (zip yox):

```bash
cd PenCentral
git pull
```

## Vacib hüquqi qeyd

Bu alət **yalnız** sənin öz infrastrukturunda, yazılı icazən olan müştəri mühitində və ya rəsmi bug-bounty scope-unda istifadə üçündür.
İcazəsiz skan bir çox ölkədə cinayətdir. Target-i özün təsdiqlə.

## Tələblər

- Python 3.10+
- PATH-də aşağıdakılardan hansı varsa, o modul işləyir; yoxdursa, o addım skip olunur.

```bash
# ProjectDiscovery (tövsiyə olunan əsas stack)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Əlavə
go install -v github.com/ffuf/ffuf/v2@latest
# və ya
# feroxbuster, nmap, assetfinder
```

Wordlist (directory enum üçün):

```text
/usr/share/seclists/Discovery/Web-Content/common.txt
```

yoxdursa `ffuf` addımı skip olunur və ya `--wordlist` ver.

## UI

```bash
cd pencentral
python3 webapp.py
```

Aç: http://127.0.0.1:8080

- Solda modul checkbox-ları: subdomain, live, port, directory, source analiz, nuclei
- Source tab: HTML/JS/source-map içindən Google/Firebase key, secret, daxili IP, domain
- Directory enum üçün wordlist yolu
- «yazılı icazəm var» işarəsi olmadan scan getmir
- Sağda tapıntılar görünür — severity, qeyd, **baxdım** checkbox
- «Yalnız baxılmamış» filtri
- Sidebar-da hansı CLI alətlərinin quraşdırıldığı görünür

## SubDeep — güclü subdomain enum

CT log, arxiv, public passive DNS və saytın HTML/JS/source-map-indən ad çıxarır.

```bash
python3 subdeep.py -d icazeli-target.com
python3 subdeep.py -d icazeli-target.com --resolve --mutate --max-js 60
```

## CLI

```bash
cd pencentral
python3 pencentral.py --help

# Yüngül recon (subdomain + live + nuclei info/low yox)
python3 pencentral.py -d example.com --profile light

# Standart (sub + live + port + nuclei)
python3 pencentral.py -d example.com --profile standard

# Tam (üstəlik directory enum)
python3 pencentral.py -d example.com --profile full --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt

# Yalnız bəzi mərhələlər
python3 pencentral.py -d example.com --only subs,probe,nuclei

# Scope siyahısı
python3 pencentral.py -l targets.txt --profile standard
```

Nəticələr: `output/<target>/<timestamp>/`

## Niyə öz wrapper-in?

Hazır böyük alətlər (reconFTW, Osmedeus) güclüdür, amma ağırdır.
Öz wrapper-in:

- yalnız sənə lazım olan mərhələləri saxlayır
- output strukturunu sən idarə edirsən
- rate-limit / scope qaydalarını özün qoyursan
- sonra Telegram/Discord notify, HTML report əlavə etmək asandır
