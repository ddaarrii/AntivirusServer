# ============================
# Настройки
# ============================
$env:OPENSSL_CONF="C:\Program Files\OpenSSL-Win64\bin\cnf\openssl.cnf"

$ROOT_CA_NAME = "MyRootCA"
$INTERMEDIATE_CA_NAME = "MyIntermediateCA"
$SERVER_CN = "localhost"
$PASSWORD = "changeit"   # пароль для keystore.p12

# Папка для выходных файлов
$OUTDIR = Join-Path (Get-Location) "certs"
if (!(Test-Path $OUTDIR)) {
    New-Item -ItemType Directory -Force -Path $OUTDIR | Out-Null
}
Set-Location $OUTDIR

# ============================
# 1. Создаём Root CA
# ============================
Write-Host "=== 1. Создаём Root CA ==="
openssl genrsa -out rootCA.key 4096
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 -out rootCA.pem `
    -subj "/C=RU/ST=Moscow/L=Moscow/O=Antivirus/OU=CA/CN=$ROOT_CA_NAME"

# ============================
# 2. Создаём Intermediate CA
# ============================
Write-Host "=== 2. Создаём Intermediate CA ==="
openssl genrsa -out intermediateCA.key 4096
openssl req -new -key intermediateCA.key -out intermediateCA.csr `
    -subj "/C=RU/ST=Moscow/L=Moscow/O=Antivirus/OU=CA/CN=$INTERMEDIATE_CA_NAME"

# Создаём временный файл с расширением для Intermediate CA
$extFile = "intermediate_ext.cnf"
"basicConstraints=CA:TRUE" | Out-File -Encoding ASCII $extFile

openssl x509 -req -in intermediateCA.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial `
    -out intermediateCA.pem -days 1825 -sha256 -extfile $extFile

Remove-Item $extFile

# ============================
# 3. Создаём Server Certificate
# ============================
Write-Host "=== 3. Создаём Server Certificate ==="
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr `
    -subj "/C=RU/ST=Moscow/L=Moscow/O=Antivirus/OU=Server/CN=$SERVER_CN"

openssl x509 -req -in server.csr -CA intermediateCA.pem -CAkey intermediateCA.key -CAcreateserial `
    -out server.crt -days 825 -sha256

# ============================
# 4. Собираем полную цепочку
# ============================
Write-Host "=== 4. Собираем полную цепочку ==="
Get-Content server.crt, intermediateCA.pem, rootCA.pem | Set-Content fullchain.crt -Encoding ASCII

# ============================
# 5. Создаём PKCS#12 keystore для Spring Boot
# ============================
Write-Host "=== 5. Создаём PKCS#12 keystore ==="
openssl pkcs12 -export -in server.crt -inkey server.key -certfile intermediateCA.pem `
    -out keystore.p12 -name myserver -password "pass:$PASSWORD"

# ============================
# 6. Итоги
# ============================
Write-Host "=== DONE! ==="
Write-Host "Root CA:          $OUTDIR\rootCA.pem"
Write-Host "Intermediate CA:  $OUTDIR\intermediateCA.pem"
Write-Host "Server Cert:      $OUTDIR\server.crt"
Write-Host "Full Chain:       $OUTDIR\fullchain.crt"
Write-Host "Keystore:         $OUTDIR\keystore.p12"
Write-Host "Keystore Password: $PASSWORD"
