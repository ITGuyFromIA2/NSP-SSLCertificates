function ConvertTo-NSPSslPem {
    # DER bytes -> one PEM block (base64 wrapped at 64 characters, LF line endings, as openssl writes it).
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][byte[]]$Bytes
    )

    $base64 = [Convert]::ToBase64String($Bytes)
    $lines = for ($i = 0; $i -lt $base64.Length; $i += 64) { $base64.Substring($i, [Math]::Min(64, $base64.Length - $i)) }
    "-----BEGIN $Label-----`n" + ($lines -join "`n") + "`n-----END $Label-----`n"
}
