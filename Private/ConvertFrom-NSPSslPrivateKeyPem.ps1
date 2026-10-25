function ConvertFrom-NSPSslPrivateKeyPem {
    # Unencrypted RSA private key PEM -> RSAParameters. Reads PKCS#8 (BEGIN PRIVATE KEY: this module,
    # openssl 3) and PKCS#1 (BEGIN RSA PRIVATE KEY: openssl 1.x, the WSL-era Rebase scripts).
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.RSAParameters])]
    param([Parameter(Mandatory)][string]$Text)

    $block = @(ConvertFrom-NSPSslPem -Text $Text | Where-Object Label -Match 'PRIVATE KEY$') | Select-Object -First 1
    if (-not $block) { throw 'No private key found in the key file.' }
    if ($block.Label -eq 'ENCRYPTED PRIVATE KEY' -or -not $block.Bytes) { throw 'The key file is password-protected; decrypt it first (openssl pkey -in <file> -out <new file>).' }

    $der = $block.Bytes
    if ($block.Label -eq 'PRIVATE KEY') {
        # PrivateKeyInfo: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { RSAPrivateKey } }
        $outer = Read-NSPSslDerElement -Bytes $der
        $version = Read-NSPSslDerElement -Bytes $outer.Content
        $algorithm = Read-NSPSslDerElement -Bytes $outer.Content -Offset $version.Next
        $oid = Read-NSPSslDerElement -Bytes $algorithm.Content
        if ([BitConverter]::ToString($oid.Content) -ne '2A-86-48-86-F7-0D-01-01-01') { throw 'The key file holds a non-RSA key; only RSA keys are supported.' }
        $der = (Read-NSPSslDerElement -Bytes $outer.Content -Offset $algorithm.Next).Content
    } elseif ($block.Label -ne 'RSA PRIVATE KEY') {
        throw "Unsupported key type: $($block.Label)."
    }

    # RSAPrivateKey: SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }
    $sequence = (Read-NSPSslDerElement -Bytes $der).Content
    $values = [Collections.Generic.List[byte[]]]::new()
    $offset = 0
    while ($offset -lt $sequence.Length -and $values.Count -lt 9) {
        $element = Read-NSPSslDerElement -Bytes $sequence -Offset $offset
        $content = $element.Content
        $start = 0
        while ($start -lt $content.Length - 1 -and $content[$start] -eq 0) { $start++ }
        $values.Add([byte[]]$content[$start..($content.Length - 1)])
        $offset = $element.Next
    }
    if ($values.Count -lt 9) { throw 'The RSA private key is incomplete.' }

    # .NET wants D the modulus' length and the CRT values half of it, left-padded with zeros.
    $pad = {
        param([byte[]]$Value, [int]$Length)
        if ($Value.Length -ge $Length) { return , $Value }
        , [byte[]]((New-Object byte[] ($Length - $Value.Length)) + $Value)
    }
    $size = $values[1].Length
    $half = [int][Math]::Ceiling($size / 2)
    $parameters = New-Object System.Security.Cryptography.RSAParameters
    $parameters.Modulus = $values[1]
    $parameters.Exponent = $values[2]
    $parameters.D = & $pad $values[3] $size
    $parameters.P = & $pad $values[4] $half
    $parameters.Q = & $pad $values[5] $half
    $parameters.DP = & $pad $values[6] $half
    $parameters.DQ = & $pad $values[7] $half
    $parameters.InverseQ = & $pad $values[8] $half
    $parameters
}
