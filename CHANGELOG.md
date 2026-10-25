# Changelog

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
