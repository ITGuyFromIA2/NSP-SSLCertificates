function Read-NSPSslDerElement {
    # The DER element at Offset: Tag, Content (bytes), and Next (the offset just past it).
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [int]$Offset = 0
    )

    if ($Offset + 2 -gt $Bytes.Length) { throw 'Truncated DER data.' }
    $tag = $Bytes[$Offset]
    $length = [int]$Bytes[$Offset + 1]
    $position = $Offset + 2
    if ($length -band 0x80) {
        $count = $length -band 0x7F
        if ($count -lt 1 -or $count -gt 4) { throw 'Unsupported DER length.' }
        $length = 0
        for ($i = 0; $i -lt $count; $i++) { $length = ($length -shl 8) -bor $Bytes[$position + $i] }
        $position += $count
    }
    if ($position + $length -gt $Bytes.Length) { throw 'Truncated DER data.' }
    $content = if ($length) { [byte[]]$Bytes[$position..($position + $length - 1)] } else { [byte[]]@() }
    [pscustomobject]@{ Tag = $tag; Content = $content; Next = $position + $length }
}
