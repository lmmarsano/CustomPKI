# CustomPKI
Extends the pki module with a proxy of `New-SelfSignedCertificate` that adds `-SAN`\* and `-EKU` parameters to reduce abstruse coding.
See the full documentation about the parameters.

```PowerShell
Help -Name CustomPKI\New-SelfSignedCertificate -Full
```

# Requires
- PowerShell V5
- [PKI Module][pki]: natively included with Windows

# Installation

```PowerShell
Install-Module -Name CustomPKI -Scope CurrentUser
```
or your preferred *scope*.

# Usage
To import the module, run

```PowerShell
Import-Module -Name CustomPKI
```

`New-SelfSignedCertificate` should now be extended.
`New-EKU` also becomes available: this creates an Enhanced Key Usages object from piped friendly names for OIDs.

# References
- [New-SelfSignedCertificate][nss]
- [PKI Module][pki]

[nss]: https://docs.microsoft.com/en-us/powershell/module/pkiclient/new-selfsignedcertificate
[pki]: https://docs.microsoft.com/en-us/powershell/module/pkiclient
