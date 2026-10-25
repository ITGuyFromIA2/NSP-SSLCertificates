function New-NSPSslDerInteger {
    # An unsigned big-endian number (as RSAParameters holds them) -> DER INTEGER: leading zero bytes
    # dropped, and one added back when the top bit is set so it doesn't read as negative.
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][byte[]]$Value)

    $start = 0
    while ($start -lt $Value.Length - 1 -and $Value[$start] -eq 0) { $start++ }
    $trimmed = [byte[]]$Value[$start..($Value.Length - 1)]
    if ($trimmed[0] -band 0x80) { $trimmed = [byte[]](@([byte]0) + $trimmed) }
    New-NSPSslDerElement -Tag 0x02 -Content $trimmed
}
