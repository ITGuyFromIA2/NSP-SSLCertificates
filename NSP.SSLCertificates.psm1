foreach ($folder in 'Private', 'Public') {
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot $folder) -Filter '*.ps1') { . $file.FullName }
}
$public = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1')
Export-ModuleMember -Function $public.BaseName
