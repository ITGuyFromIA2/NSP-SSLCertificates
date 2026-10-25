function Read-NSPSslCertificateFile {
    # Every certificate in a file: PEM (one or many, as issuers' .crt/.pem/.ca-bundle files hold them),
    # DER (.cer), or PKCS#7 (.p7b, PEM or DER).
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param([Parameter(Mandatory)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    $text = [Text.Encoding]::ASCII.GetString($bytes)
    $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    if ($text -match '-----BEGIN ') {
        foreach ($block in ConvertFrom-NSPSslPem -Text $text) {
            if ($block.Label -in 'CERTIFICATE', 'TRUSTED CERTIFICATE', 'PKCS7', 'X509 CERTIFICATE') { $collection.Import($block.Bytes) }
        }
    } else {
        # A DER certificate or a DER PKCS#7 bundle; Import reads both.
        $collection.Import($bytes)
    }
    foreach ($certificate in $collection) { $certificate }
}
