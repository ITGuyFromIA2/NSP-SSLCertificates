@{
    IncludeDefaultRules = $true
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # Start-NSPSslManager is an interactive menu - coloured output via Write-Host is deliberate.
        'PSAvoidUsingWriteHost'

        # Fires on private New- helpers that only build bytes; the public commands that write files
        # or certificate stores declare SupportsShouldProcess.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
