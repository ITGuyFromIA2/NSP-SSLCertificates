function Test-NSPSslSelfSigned {
    # A root: issued by itself. Judged by the encoded names, never by what the certificate is called -
    # a cross-signed "... Root CA - R1" issued by an older root is an intermediate.
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    [Convert]::ToBase64String($Certificate.SubjectName.RawData) -eq [Convert]::ToBase64String($Certificate.IssuerName.RawData)
}
