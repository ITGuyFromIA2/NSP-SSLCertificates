function ConvertFrom-NSPSslSecureString {
    # SecureString -> plain text, for the one .NET call that needs it (PFX export/import).
    # Windows PowerShell has no ConvertFrom-SecureString -AsPlainText.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][securestring]$SecureString)

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}
