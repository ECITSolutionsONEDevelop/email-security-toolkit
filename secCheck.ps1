# Ensure required modules are installed
$modules = @("Microsoft.Graph", "DomainHealthChecker")
foreach ($module in $modules) {
    if (-not (Get-Module -Name $module -ListAvailable)) {
        Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
    }
}

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Domain.Read.All, Organization.Read.All", "Directory.Read.All" -NoWelcome

# Get the tenant ID
$tenantId = (Get-MgOrganization).Id

# Fetch all domains
$domains = Get-MgDomain

# Create an array to hold domain information
$domainsToCheck = @()

# Populate the array with domain details
$domains | ForEach-Object {
    $domainInfo = [PSCustomObject]@{
        DomainName = $_.Id
        IsDefault   = $_.IsDefault
        IsVerified  = $_.IsVerified
    }
    $domainsToCheck += $domainInfo
}

Write-Output "Domains have been fetched from Microsoft 365"
Disconnect-MgGraph

# Create an array to hold domain security information
$domainSecList = @()

# Loop through each domain
$domainsToCheck | ForEach-Object {
    # Get the domain name
    $domainName = $_.DomainName

    # Get the domain status (Focus on selector1 for DKIM since thats what Microsoft 365 uses)
    $secStatus = Invoke-SpfDkimDmarc -DkimSelector "selector1" -Name $domainName

    # Get number of DNS queries for SPF record
    $dnsQueryCount = Resolve-SPFRecord -Name $domainName | Select-Object -Unique SPFSourceDomain | Measure-Object | Select-Object -ExpandProperty Count

    # Make a new object with the domain name and security status
    $domainSecInfo = [PSCustomObject]@{
        DomainName = $domainName
        IsDefault = $_.IsDefault
        IsVerified = $_.IsVerified
        SpfLookupCount = $dnsQueryCount
        SpfRecord = $secStatus.SpfRecord
        SpfAdvisory = $secStatus.SpfAdvisory
        DkimSelector = $secStatus.DkimSelector
        DkimAdvisory = $secStatus.DkimAdvisory
        DmarcRecord = $secStatus.DmarcRecord
        DmarcAdvisory = $secStatus.DmarcAdvisory
    }
    $domainSecList += $domainSecInfo
}

# Check that the output directory exists
if (-not (Test-Path -Path "C:\temp")) {
    New-Item -Path "C:\temp" -ItemType Directory
}

# Export the domain information to a CSV file
$currentDateTime = Get-Date -Format "HH-mm-dd-MM-yyyy"
$path = "C:\temp\$tenantId-emailsec-status-$currentDateTime.csv"
$domainSecList | Export-Csv -Path $path -NoTypeInformation
Write-Output "Report has been generated and saved to $path"

# Supporting function to get SPF DNS Lookup Count
function Resolve-SPFRecord {
    [CmdletBinding()]
    param (
        # Domain Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [string]$Name,

        # DNS Server to use
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 2)]
        [string]$Server = "1.1.1.1",

        # If called nested provide a referrer to build valid objects
        [Parameter(Mandatory = $false)]
        [string]$Referrer
    )

    begin {
        class SPFRecord {
            [string] $SPFSourceDomain
            [string] $IPAddress
            [string] $Referrer
            [string] $Qualifier
            [bool] $Include

            # Constructor: Creates a new SPFRecord object, with a specified IPAddress
            SPFRecord ([string] $IPAddress) {
                $this.IPAddress = $IPAddress
            }

            # Constructor: Creates a new SPFRecord object, with a specified IPAddress and DNSName
            SPFRecord ([string] $IPAddress, [String] $DNSName) {
                $this.IPAddress = $IPAddress
                $this.SPFSourceDomain = $DNSName
            }

            # Constructor: Creates a new SPFRecord object, with a specified IPAddress and DNSName and
            SPFRecord ([string] $IPAddress, [String] $DNSName, [String] $Qualifier) {
                $this.IPAddress = $IPAddress
                $this.SPFSourceDomain = $DNSName
                $this.Qualifier = $Qualifier
            }
        }
    }

    process {
        # Keep track of number of DNS queries
        # DNS Lookup Limit = 10
        # https://tools.ietf.org/html/rfc7208#section-4.6.4
        # Query DNS Record
        $DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type TXT
        # Check SPF record
        $SPFRecord = $DNSRecords | Where-Object { $_.Strings -match "^v=spf1" }
        # Validate SPF record
        $SPFCount = ($SPFRecord | Measure-Object).Count

        if ( $SPFCount -eq 0) {
            # If there is no error show an error
            write-verbose "No SPF record found for `"$Name`""
        }
        elseif ( $SPFCount -ge 2 ) {
            # Multiple DNS Records are not allowed
            # https://tools.ietf.org/html/rfc7208#section-3.2
            write-verbose "There is more than one SPF for domain `"$Name`"" -Verbose
        }
        else {
            # Multiple Strings in a Single DNS Record
            # https://tools.ietf.org/html/rfc7208#section-3.3
            $SPFString = $SPFRecord.Strings -join ''
            # Split the directives at the whitespace
            $SPFDirectives = $SPFString -split " "

            # Check for a redirect
            if ( $SPFDirectives -match "redirect" ) {
                $RedirectRecord = $SPFDirectives -match "redirect" -replace "redirect="
                Write-Verbose "[REDIRECT]`t$RedirectRecord"
                # Follow the include and resolve the include
                Resolve-SPFRecord -Name "$RedirectRecord" -Server $Server -Referrer $Name
            }
            else {

                # Extract the qualifier
                $Qualifier = switch ( $SPFDirectives -match "^[+-?~]all$" -replace "all" ) {
                    "+" { "pass" }
                    "-" { "fail" }
                    "~" { "softfail" }
                    "?" { "neutral" }
                }

                $ReturnValues = foreach ($SPFDirective in $SPFDirectives) {
                    switch -Regex ($SPFDirective) {
                        "%[{%-_]" {
                            write-verbose "[$_]`tMacros are not supported. For more information, see https://tools.ietf.org/html/rfc7208#section-7"
                            Continue
                        }
                        "^exp:.*$" {
                            write-verbose "[$_]`tExplanation is not supported. For more information, see https://tools.ietf.org/html/rfc7208#section-6.2"
                            Continue
                        }
                        '^include:.*$' {
                            # Follow the include and resolve the include
                            Resolve-SPFRecord -Name ( $SPFDirective -replace "^include:" ) -Server $Server -Referrer $Name
                        }
                        '^ip[46]:.*$' {
                            Write-Verbose "[IP]`tSPF entry: $SPFDirective"
                            $SPFObject = [SPFRecord]::New( ($SPFDirective -replace "^ip[46]:"), $Name, $Qualifier)
                            if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                $SPFObject.Referrer = $Referrer
                                $SPFObject.Include = $true
                            }
                            $SPFObject
                        }
                        '^a:.*$' {
                            Write-Verbose "[A]`tSPF entry: $SPFDirective"
                            $DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type A
                            # Check SPF record
                            foreach ($IPAddress in ($DNSRecords.IPAddress) ) {
                                $SPFObject = [SPFRecord]::New( $IPAddress, ($SPFDirective -replace "^a:"), $Qualifier)
                                if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                    $SPFObject.Referrer = $Referrer
                                    $SPFObject.Include = $true
                                }
                                $SPFObject
                            }
                        }
                        '^mx:.*$' {
                            Write-Verbose "[MX]`tSPF entry: $SPFDirective"
                            $DNSRecords = Resolve-DnsName -Server $Server -Name $Name -Type MX
                            foreach ($MXRecords in ($DNSRecords.NameExchange) ) {
                                # Check SPF record
                                $DNSRecords = Resolve-DnsName -Server $Server -Name $MXRecords -Type A
                                foreach ($IPAddress in ($DNSRecords.IPAddress) ) {
                                    $SPFObject = [SPFRecord]::New( $IPAddress, ($SPFDirective -replace "^mx:"), $Qualifier)
                                    if ( $PSBoundParameters.ContainsKey('Referrer') ) {
                                        $SPFObject.Referrer = $Referrer
                                        $SPFObject.Include = $true
                                    }
                                    $SPFObject
                                }
                            }
                        }
                        Default {
                            write-verbose "[$_]`t Unknown directive"
                        }
                    }
                }

                $DNSQuerySum = $ReturnValues | Select-Object -Unique SPFSourceDomain | Measure-Object | Select-Object -ExpandProperty Count
                if ( $DNSQuerySum -gt 6) {
                    write-verbose "Watch your includes!`nThe maximum number of DNS queries is 10 and you have already $DNSQuerySum.`nCheck https://tools.ietf.org/html/rfc7208#section-4.6.4"
                }
                if ( $DNSQuerySum -gt 10) {
                    write-verbose "Too many DNS queries made ($DNSQuerySum).`nMust not exceed 10 DNS queries.`nCheck https://tools.ietf.org/html/rfc7208#section-4.6.4"
                }

                $ReturnValues
            }
        }
    }

    end {

    }
}