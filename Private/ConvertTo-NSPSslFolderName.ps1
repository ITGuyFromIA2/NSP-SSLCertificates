function ConvertTo-NSPSslFolderName {
    # A request's folder (and file) name: the domain in lower case, with a wildcard's '*' spelled out
    # ('*.contoso.com' -> 'wildcard.contoso.com') since Windows paths can't hold it.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Domain)

    ($Domain.ToLowerInvariant()) -replace '^\*\.', 'wildcard.'
}
