function Get-NSPSslDnsName {
    # The DNS names a certificate covers, lower case: its subject alternative names (dNSName entries),
    # or the common name when it has none. Read from the extension itself - PowerShell's DnsNameList
    # is a type extension that isn't reliable across editions.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $extension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
    if ($extension) {
        # SubjectAltName: SEQUENCE OF GeneralName; dNSName is [2] IA5String.
        $names = (Read-NSPSslDerElement -Bytes $extension.RawData).Content
        $offset = 0
        while ($offset -lt $names.Length) {
            $element = Read-NSPSslDerElement -Bytes $names -Offset $offset
            if ($element.Tag -eq 0x82) { [Text.Encoding]::ASCII.GetString($element.Content).ToLowerInvariant() }
            $offset = $element.Next
        }
        return
    }
    $commonName = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false)
    if ($commonName) { $commonName.ToLowerInvariant() }
}
