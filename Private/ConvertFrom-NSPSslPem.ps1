function ConvertFrom-NSPSslPem {
    # Every PEM block in a text: Label (CERTIFICATE, PRIVATE KEY, PKCS7, ...) and the DER Bytes.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $pattern = '-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----'
    foreach ($match in [regex]::Matches($Text, $pattern, [Text.RegularExpressions.RegexOptions]::Singleline)) {
        $body = $match.Groups[2].Value -replace '\s', ''
        # Encrypted PEM (Proc-Type headers) isn't base64 throughout; leave it to the caller to reject.
        if ($body -match ':') { $bytes = $null } else { $bytes = [Convert]::FromBase64String($body) }
        [pscustomobject]@{ Label = $match.Groups[1].Value; Bytes = $bytes }
    }
}
