function Get-NSPSslWorkRoot {
    # Where request folders live: -Path, else $env:NSP_SSL_PATH, else Documents\NSP-SSLCertificates.
    # Request folders hold private keys - keep them out of Git repositories.
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Path)

    if ($Path) { return $Path }
    if ($env:NSP_SSL_PATH) { return $env:NSP_SSL_PATH }
    Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'NSP-SSLCertificates'
}
