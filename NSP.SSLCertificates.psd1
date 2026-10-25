@{
    RootModule = 'NSP.SSLCertificates.psm1'
    ModuleVersion = '0.1.0'
    GUID = '104a1088-c5a5-4c4a-ba76-6ad5485ecf22'
    Author = 'Network Systems Plus'
    CompanyName = 'Network Systems Plus'
    Copyright = '(c) Network Systems Plus. All rights reserved.'
    Description = 'Public SSL certificates from request to install: generate a private key and CSR, turn the issuer''s ZIP into a certificate, full-chain PEM and PFX, and import a PFX on Windows with the certificate, intermediates and roots each in the right store. Native PowerShell - no WSL or openssl. Windows PowerShell 5.1 compatible.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'New-NSPSslRequest'
        'Complete-NSPSslRequest'
        'Get-NSPSslRequest'
        'Start-NSPSslManager'
        'Import-NSPSslPfx'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('NSP', 'SSL', 'TLS', 'Certificate', 'CSR', 'PFX', 'PKCS12', 'IIS', 'FortiGate', 'Windows')
            ProjectUri = 'https://github.com/ITGuyFromIA2/NSP-SSLCertificates'
            LicenseUri = 'https://github.com/ITGuyFromIA2/NSP-SSLCertificates/blob/main/LICENSE'
            ReleaseNotes = '0.1.0: first release, replacing the WSL/openssl scripts in NSP-SSLCertificates (Rebase).'
        }
    }
}
