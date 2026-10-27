function Resolve-NSPSslBindingSelection {
    # The binding numbers (1-based) an answer picks: blank = the proposed ones, A = every selectable
    # one, N = none, or a list like "1,3" or "2-4". Throws on a number out of range or one that can't
    # be rebound (already on the certificate, Central Certificate Store).
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [AllowEmptyString()][string]$Answer,
        [Parameter(Mandatory)][int]$Count,
        [AllowEmptyCollection()][int[]]$Proposed = @(),
        [AllowEmptyCollection()][int[]]$Selectable = @()
    )

    $text = "$Answer".Trim()
    if (-not $text) { return $Proposed }
    if ($text -match '^(?i)n(one)?$') { return }
    if ($text -match '^(?i)a(ll)?$') { return $Selectable }

    $picked = [Collections.Generic.List[int]]::new()
    foreach ($part in ($text -split '[,\s]+' | Where-Object { $_ })) {
        if ($part -match '^(\d+)-(\d+)$') { $range = [int]$Matches[1]..[int]$Matches[2] }
        elseif ($part -match '^\d+$') { $range = @([int]$part) }
        else { throw "'$part' isn't a binding number." }
        foreach ($number in $range) {
            if ($number -lt 1 -or $number -gt $Count) { throw "There's no binding $number." }
            if ($number -notin $Selectable) { throw "Binding $number can't be rebound (see its note)." }
            if (-not $picked.Contains($number)) { $picked.Add($number) }
        }
    }
    $picked
}
