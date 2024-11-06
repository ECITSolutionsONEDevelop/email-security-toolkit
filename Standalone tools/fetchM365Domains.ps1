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
$currentDateTime = Get-Date -Format "HH-mm-dd-MM-yyyy"
$path = "C:\temp\RegisteredDomains-$currentDateTime.csv"
$domainList | Export-Csv -Path $path -NoTypeInformation
Write-Output "Domain export report has been generated and saved to $path"

# Disconnect from Microsoft Graph
Disconnect-MgGraph