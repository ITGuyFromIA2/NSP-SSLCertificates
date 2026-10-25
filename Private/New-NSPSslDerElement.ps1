function New-NSPSslDerElement {
    # One DER element: tag, definite length, content. Enough ASN.1 to write an RSA private key.
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)][byte]$Tag,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Content
    )

    $length = $Content.Length
    if ($length -lt 0x80) {
        $header = [byte[]]@($Tag, $length)
    } else {
        $lengthBytes = [Collections.Generic.List[byte]]::new()
        while ($length -gt 0) { $lengthBytes.Insert(0, [byte]($length -band 0xFF)); $length = $length -shr 8 }
        $header = [byte[]](@($Tag, (0x80 -bor $lengthBytes.Count)) + $lengthBytes.ToArray())
    }
    , [byte[]]($header + $Content)
}
