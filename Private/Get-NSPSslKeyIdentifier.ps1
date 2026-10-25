function Get-NSPSslKeyIdentifier {
    # A certificate's Subject Key Identifier, or the key identifier in its Authority Key Identifier
    # (what its issuer's SKI should be), as hex. Empty when the extension isn't there.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)][ValidateSet('Subject', 'Authority')][string]$Kind
    )

    if ($Kind -eq 'Subject') {
        $extension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.14' } | Select-Object -First 1
        if (-not $extension) { return '' }
        return ([System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]$extension).SubjectKeyIdentifier.ToUpperInvariant()
    }

    # AuthorityKeyIdentifier: SEQUENCE { [0] keyIdentifier OPTIONAL, ... }
    $extension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.35' } | Select-Object -First 1
    if (-not $extension) { return '' }
    try {
        $sequence = (Read-NSPSslDerElement -Bytes $extension.RawData).Content
        if (-not $sequence.Length) { return '' }
        $first = Read-NSPSslDerElement -Bytes $sequence
        if ($first.Tag -ne 0x80) { return '' }
        ([BitConverter]::ToString($first.Content) -replace '-', '').ToUpperInvariant()
    } catch {
        ''
    }
}
