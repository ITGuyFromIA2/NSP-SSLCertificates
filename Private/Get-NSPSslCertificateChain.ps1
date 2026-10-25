function Get-NSPSslCertificateChain {
    # The issuers of a certificate, in order (its issuer first), found among Candidates by name and,
    # where both carry one, by key identifier. Stops at a root (self-signed) or when the next issuer
    # isn't among the candidates - issuers usually leave the root out.
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [AllowEmptyCollection()][System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Candidates = @()
    )

    $chain = [Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
    $used = @{ $Certificate.Thumbprint = $true }
    $current = $Certificate
    while (-not (Test-NSPSslSelfSigned -Certificate $current) -and $chain.Count -lt 10) {
        $issuerName = [Convert]::ToBase64String($current.IssuerName.RawData)
        $matching = @($Candidates | Where-Object { -not $used.ContainsKey($_.Thumbprint) -and [Convert]::ToBase64String($_.SubjectName.RawData) -eq $issuerName })
        if (-not $matching) { break }
        $authorityKey = Get-NSPSslKeyIdentifier -Certificate $current -Kind Authority
        $issuer = $null
        if ($authorityKey) { $issuer = $matching | Where-Object { (Get-NSPSslKeyIdentifier -Certificate $_ -Kind Subject) -eq $authorityKey } | Select-Object -First 1 }
        if (-not $issuer) { $issuer = $matching[0] }
        $chain.Add($issuer)
        $used[$issuer.Thumbprint] = $true
        $current = $issuer
    }
    foreach ($link in $chain) { $link }
}
