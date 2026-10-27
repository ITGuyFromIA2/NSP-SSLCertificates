function Remove-NSPSslStoreCertificate {
    # Deletes a certificate from LocalMachine\My together with its private key (a plain store removal
    # leaves the key file behind).
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Thumbprint)

    $item = "Cert:\LocalMachine\My\$Thumbprint"
    if (-not (Test-Path -LiteralPath $item)) { return }
    if ($PSCmdlet.ShouldProcess($item, 'Delete the certificate and its private key')) {
        Remove-Item -LiteralPath $item -DeleteKey -ErrorAction Stop
    }
}
