# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Domain.Read.All"

# Fetch all domains
$domains = Get-MgDomain

# Create an array to hold domain information
$domainList = @()

# Populate the array with domain details
$domains | ForEach-Object {
    $domainInfo = [PSCustomObject]@{
        DomainName = $_.Id
        IsDefault   = $_.IsDefault
        IsVerified  = $_.IsVerified
    }
    $domainList += $domainInfo
}

# Export the domain information to a CSV file
$domainList | Export-Csv -Path "RegisteredDomains.csv" -NoTypeInformation

# Disconnect from Microsoft Graph
Disconnect-MgGraph

Write-Output "Domains have been exported to RegisteredDomains.csv"