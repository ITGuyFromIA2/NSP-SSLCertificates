function New-NSPSslRsa {
    # A throwaway RSA object for a key: new (-KeySize) or from RSAParameters. Never persisted to a key
    # container; dispose it when done.
    [CmdletBinding(DefaultParameterSetName = 'New')]
    [OutputType([System.Security.Cryptography.RSA])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'New')][int]$KeySize,
        [Parameter(Mandatory, ParameterSetName = 'Import')][System.Security.Cryptography.RSAParameters]$Parameters
    )

    if ($PSCmdlet.ParameterSetName -eq 'New') {
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider $KeySize
    } else {
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.ImportParameters($Parameters)
    }
    $rsa.PersistKeyInCsp = $false
    $rsa
}
