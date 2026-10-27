function Find-NSPSslTrustedRoot {
    # The self-signed root that issued Certificate, from this machine's trusted roots: Trusted Root
    # (Root) or Third-Party Root (AuthRoot, where Windows' automatic root update puts them).
    # Matched by name and, where the certificate carries one, by key identifier. Issuers usually
    # leave the root out of their downloads (GoDaddy's IIS bundle stops at the cross-signed
    # Root CA - R1), so this is how the PFX gets it.
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    if (Test-NSPSslSelfSigned -Certificate $Certificate) { return }
    $issuerName = [Convert]::ToBase64String($Certificate.IssuerName.RawData)
    $authorityKey = Get-NSPSslKeyIdentifier -Certificate $Certificate -Kind Authority
    foreach ($storeName in 'Root', 'AuthRoot') {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store $storeName, 'LocalMachine'
        try {
            $store.Open('ReadOnly')
            $found = $store.Certificates | Where-Object {
                [Convert]::ToBase64String($_.SubjectName.RawData) -eq $issuerName -and
                (Test-NSPSslSelfSigned -Certificate $_) -and
                (-not $authorityKey -or (Get-NSPSslKeyIdentifier -Certificate $_ -Kind Subject) -eq $authorityKey)
            } | Sort-Object NotAfter -Descending | Select-Object -First 1
            if ($found) { return $found }
        } catch {
            Write-Verbose "Could not read LocalMachine\$($storeName): $($_.Exception.Message)"
        } finally {
            $store.Close()
        }
    }
}
