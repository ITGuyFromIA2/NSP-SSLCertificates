# NSP.SSLCertificates

Public SSL certificates from request to install, in native PowerShell. Windows PowerShell **5.1**
compatible (and 7+). No WSL, openssl, or unzip. NSP.Bootstrap is loaded only for an elevated
import.

Replaces the WSL/openssl scripts in the NSP-SSLCertificates repository (`Rebase\Wrapper.sh`,
`1_Gen_NewPrivKey_And_CSR.sh`, `2_CombineCerts.sh`).

## The workflow

```powershell
Start-NSPSslManager            # the menu: same flow as Wrapper.sh (number = finish, N = new, Q = quit)
```

Or step by step:

```powershell
# 1. Key + CSR. The CSR goes to the clipboard; paste it into the issuer's order page.
New-NSPSslRequest -Domain vpn.contoso.com -CopyToClipboard

# 2. When it's issued, download it in IIS format and drop the ZIP in the request's Inputs folder.
Get-NSPSslRequest              # AwaitingCertificate -> CertificateReady -> Completed

# 3. Build the deliverables (prompts for the PFX password).
Complete-NSPSslRequest -Domain vpn.contoso.com
```

Request folders live in `Documents\NSP-SSLCertificates` (or `$env:NSP_SSL_PATH`, or `-Path`):

```
vpn.contoso.com\
    request.json                     names and subject used
    Inputs\                          the issuer's ZIP goes here
    Deliverables\
        vpn.contoso.com.csr
        vpn.contoso.com_priv.key     unencrypted PKCS#8 PEM - protect this folder
        vpn.contoso.com.crt          certificate (PEM)
        vpn.contoso.com_intermediates.crt
        vpn.contoso.com_FullChain.pem    certificate + intermediates (FortiGate, nginx, Apache)
        vpn.contoso.com.pfx          certificate + intermediates + root + key (Windows, IIS)
        vpn.contoso.com_Install\     copy of the PFX + Install-vpn.contoso.com.cmd/.ps1 (for the server)
```

## Installing on a Windows server (the client side)

Copy the request's `<domain>_Install` folder to the server and double-click
`Install-<domain>.cmd`. It's an NSP.ClientScripts ToolShim, and it runs these steps:

1. Elevates (UAC).
2. Installs NSP.SSLCertificates, NSP.Console and NSP.IIS from the PowerShell Gallery.
3. Runs `Install-NSPSslCertificate` in that folder:
   - **Import:** asks for the PFX password, then places each certificate in the right store
     (table below). If the chain doesn't validate because the root isn't trusted (no Windows
     Update), it offers to add the root the PFX carries.
   - **IIS** (when installed): lists the https bindings with their current certificates and marks
     with `*` the ones the new certificate belongs on. A binding is marked when its host name is on
     the certificate, or, with no host name, when its current certificate covers the same names.
     Enter takes the marked ones; `1,3`, `2-4`, `A` or `N` choose otherwise. Matching and
     rebinding are in [NSP.IIS](https://github.com/ITGuyFromIA2/NSP-IIS).
   - **Old certificate:** for each certificate a binding was moved off, if no IIS or other http.sys
     binding still uses it, offers to delete it and its key (default no). Services that load a
     certificate themselves (RDP, SQL Server, LDAPS, Exchange) aren't checked.
4. Waits for Enter, so the results stay on screen.

`Install-NSPSslCertificate -Path <pfx>` does the same from a prompt. `-SkipIis` imports only.

### Import only

```powershell
Import-NSPSslPfx -Path .\vpn.contoso.com.pfx                     # LocalMachine; relaunches elevated if needed
Import-NSPSslPfx -Path .\vpn.contoso.com.pfx -WhatIf             # show where each certificate would go
Import-NSPSslPfx -Path .\portal.contoso.com.pfx -ChainFile .\CAR1.cer, .\G2.cer -TrustRoot
```

`Import-PfxCertificate` drops every certificate in a PFX into the one store you name, so the
intermediates end up in Personal next to the certificate, and an intermediate imported into
Trusted Root becomes a trust anchor. `Import-NSPSslPfx` places them the way the Certificate Import
Wizard's automatic placement does:

| Certificate | Store |
|---|---|
| the one with the private key | `My` (Personal) |
| intermediates: not self-signed | `CA` (Intermediate Certification Authorities) |
| roots: self-signed | `Root`, only with `-TrustRoot` (otherwise reported and skipped) |

A certificate counts as a root only if it issued itself, never because of its name. Starfield's
current DV bundle is the reason: it carries **Starfield TLS Root CA - R1 cross-signed by Starfield
Root Certificate Authority - G2**. Despite the name, that copy is an intermediate, and it belongs
in `CA`.

Certificates already in place are left alone. Afterwards the certificate's chain is built (no
revocation check) and reported (`Chain`, `ChainStatus`). The key is not exportable unless you pass
`-Exportable`.

From a non-elevated session, a LocalMachine import relaunches itself in a new elevated window
(NSP.Bootstrap's `Invoke-NSPElevated`; UAC prompt), which asks for the PFX password and shows the
results. `-NoElevate` fails instead, for scripts and RMM jobs that already run elevated. This is the
module's only NSP dependency, and it's loaded on first use (installed from the Gallery if missing).

## What changed from the WSL scripts

- One PowerShell module instead of per-domain copies of the bash scripts and `variables.sh`.
- The issuer's certificate is found by matching the private key, not by file name. A ZIP for the
  wrong request is refused, and extra files in the ZIP don't matter. The intermediates are put in
  order, and self-signed roots are left out of the PEM files (see the PFX below).
- **No default PFX password, and the password is never written to disk** (`_PFXPass.txt` is gone).
  Send it separately from the PFX.
- An existing key is never overwritten: re-running a request refuses, and `-Force` archives the
  old key and deliverables before making new ones.
- Five names per certificate, the domain included, as before; `-NoNameLimit` (on
  `New-NSPSslRequest` and `Start-NSPSslManager`) lifts it. `www.<domain>` is added by default in
  the menu (answer n to skip it) and with `-IncludeWww` from the command line, and only when a
  slot is free.
- `_pub.key` is no longer written. It's derivable from the key or certificate, and nothing used it.
- Requests started with the WSL scripts can be finished here: `-Path <the Rebase folder>` reads
  `Deliverables_<domain>\` and the PKCS#1 or PKCS#8 keys openssl wrote.
- The PFX carries the root: the issuer's copy, or this machine's trusted copy when the issuer
  left it out (GoDaddy's IIS bundle stops at the cross-signed Root CA - R1, so G2 comes from
  here). The PEM files leave it out unless `-IncludeRoot`, because a server shouldn't send its
  root.
- The PFX uses TripleDES/SHA1 (what `openssl pkcs12 -export -legacy` produced), so FortiGate and
  older Windows can import it.

## Tests

```powershell
.\tools\Test-Repo.ps1      # manifest, help, smoke checks under Windows PowerShell 5.1 and pwsh, PSScriptAnalyzer
```

`Tests\Smoke.ps1` builds a throwaway chain shaped like Starfield's (root -> cross-signed root ->
DV intermediate). It runs the request, ZIP and PFX steps against it, and then imports into the
**CurrentUser** stores and cleans up after itself. Nothing touches Trusted Root.
