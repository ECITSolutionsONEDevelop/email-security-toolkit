# Email Security Tookit

A small, easy to use toolkit to quickly discover exisiting DMARC, SPF and DKIM setups (on microsoft selectors) on all domains registered to a M365 tenant.

## Prereqs
- Powershell module: DomainHealthChecker (https://github.com/T13nn3s/Invoke-SpfDkimDmarc)
```powershell
C:\> Install-Module DomainHealthChecker
```

- Powershell module: Microsoft Graph (For all users)
```powershell
C:\> Install-Module Microsoft.Graph -Scope AllUsers -Repository PSGallery -Force
```