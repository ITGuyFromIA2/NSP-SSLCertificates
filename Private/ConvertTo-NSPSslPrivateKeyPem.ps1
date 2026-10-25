function ConvertTo-NSPSslPrivateKeyPem {
    # RSA private key -> unencrypted PKCS#8 PEM (BEGIN PRIVATE KEY), the format openssl 3 genrsa writes.
    # Windows PowerShell's .NET has no PEM export, so the ASN.1 is built here.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Security.Cryptography.RSAParameters]$Parameters)

    $p = $Parameters
    $integers = foreach ($value in @([byte[]]@(0), $p.Modulus, $p.Exponent, $p.D, $p.P, $p.Q, $p.DP, $p.DQ, $p.InverseQ)) {
        New-NSPSslDerInteger -Value $value
    }
    $rsaPrivateKey = New-NSPSslDerElement -Tag 0x30 -Content ([byte[]]($integers | ForEach-Object { $_ }))

    # AlgorithmIdentifier: rsaEncryption (1.2.840.113549.1.1.1), NULL parameters.
    $algorithm = [byte[]](0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00)
    $content = [byte[]]((New-NSPSslDerInteger -Value ([byte[]]@(0))) + $algorithm + (New-NSPSslDerElement -Tag 0x04 -Content $rsaPrivateKey))
    ConvertTo-NSPSslPem -Label 'PRIVATE KEY' -Bytes (New-NSPSslDerElement -Tag 0x30 -Content $content)
}
