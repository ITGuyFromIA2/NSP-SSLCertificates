function Test-NSPSslDnsName {
    # A name a public CA will put on a certificate: at least two labels (contoso.com, vpn.contoso.com),
    # optionally a leading wildcard (*.contoso.com).
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Name)

    $Name -match '^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
}
