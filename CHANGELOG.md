# Changelog

## 0.2.0 (2026-10-28)

- `Install-NSPSslCertificate`: the server side, start to finish, and interactive (NSP.Console):
  - imports the PFX, and offers the root when the chain doesn't validate;
  - when IIS is installed, proposes and applies the bindings the certificate belongs on (NSP.IIS);
  - offers to delete each certificate it replaced, once nothing in IIS or http.sys uses it.
- `Complete-NSPSslRequest` writes `<domain>_Install\`: a copy of the PFX and a double-click
  `Install-<domain>.cmd` (NSP.ClientScripts 0.1.6 ToolShim, starts in its folder, pauses at the
  end). `-NoInstaller` skips it.
- The PFX always carries the root: the issuer's copy, or this machine's from Root/AuthRoot when the
  issuer left it out (GoDaddy's G2). The PEM files are unchanged (`-IncludeRoot` still adds it to
  them). New output properties: `PfxRoot`, `InstallerPath`.
- `Import-NSPSslPfx`: a root trusted through Third-Party Root (AuthRoot, where Windows' automatic
  root update puts it) counts as already present instead of being reported untrusted.

## 0.1.0 (2026-10-25)

- First release. Replaces the WSL/openssl scripts in the NSP-SSLCertificates repository (`Rebase`):
  - `New-NSPSslRequest`: private key and CSR (1_Gen_NewPrivKey_And_CSR.sh). Five names at most
    unless `-NoNameLimit`; `www.<domain>` (on by default in the menu) only takes a free slot.
  - `Complete-NSPSslRequest`: the issuer's ZIP -> certificate, intermediates, full-chain PEM, PFX
    (2_CombineCerts.sh). Finds the certificate by its key, orders the chain, and leaves out
    self-signed roots. The PFX password is never saved.
  - `Get-NSPSslRequest` and `Start-NSPSslManager`: the request list and the menu (Wrapper.sh).
    Both read WSL-era request folders.
- `Import-NSPSslPfx`: the client side. Imports a PFX with the certificate in Personal,
  intermediates in Intermediate Certification Authorities, and roots in Trusted Root only on
  request; reports the resulting chain. Into LocalMachine from a non-elevated session it relaunches
  itself elevated through NSP.Bootstrap's `Invoke-NSPElevated` (loaded on first use, so the module
  still imports on a bare host); `-NoElevate` fails instead, for RMM jobs.
