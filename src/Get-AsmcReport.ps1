<#
.SYNOPSIS
Run an Azure Resource Graph kqlScenario2 query to find App Service sites using App Service Managed Certificates (ASMC)
and that commonly restrict public access (publicNetworkAccess disabled or client certificates enabled).

.DESCRIPTION
This script executes the embedded kqlScenario2 via Search-AzGraph, ensuring the required Az modules are
available, handling authentication (supports device code), optionally setting subscription context,
collecting Traffic Manager endpoints, and exporting results as CSV, JSON (stdout) or writing objects
to the pipeline.

.PARAMETER OutputPath
(Optional) Path to write CSV output. Use '-' to emit JSON to stdout. If omitted, results are written to the pipeline.

.PARAMETER TenantId
(Mandatory) Tenant Id to use for initial sign-in.

.PARAMETER UseDeviceLogin
(Optional) Use device code authentication when connecting interactively.

.PARAMETER GrantReaderAccess
(Optional) Attempt to grant Reader and Resource Graph Reader roles to current user for all subscriptions.

.NOTES
Contributors: 
Preston K. Parsard
GitHub Copilot
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "asmc-report.csv",
    [Parameter(Mandatory=$true)]
    [string]$TenantId,
    [switch]$UseDeviceLogin,
    [switch]$GrantReaderAccess
)

# Prompt for TenantId if not provided as a parameter
if (-not $TenantId -or [string]::IsNullOrWhiteSpace($TenantId)) {
    Write-Host "TenantId was not supplied. You may enter a TenantId (GUID) to use for sign-in, or press Enter to continue without specifying one."
    $userInput = Read-Host -Prompt "Enter TenantId (or press Enter to skip)"
    if ($userInput) {
        try {
            # Validate GUID format if possible
            $null = [guid]$userInput
            $TenantId = $userInput
            Write-Host "Using TenantId: $TenantId"
        }
        catch {
            # Accept non-GUID input but warn the user
            Write-Warning "Input does not match GUID format. Will use provided value as TenantId anyway."
            $TenantId = $userInput
        }
    }
    else {
        Write-Host "No TenantId specified. Authentication will proceed without an explicit tenant."
    }
}

function Install-ModuleIfMissing {
    param(
        [string]$Name
    )
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Verbose "$Name not found. Installing for current user..."
        try {
            Install-Module -Name $Name -Scope CurrentUser -Force -ErrorAction Stop
        }
        catch {
            Throw ("Failed to install {0}: {1}" -f $Name, $_)
        }
    }
    Import-Module $Name -Verbose
}

function Grant-ReaderAccessToAllSubscriptions {
    <#
    .SYNOPSIS
    Grant Reader and Resource Graph Reader roles to current user for all accessible subscriptions
    
    .DESCRIPTION
    This function attempts to grant Reader and Resource Graph Reader roles to the current user
    for all subscriptions they can see. Useful for ensuring Resource Graph access.
    #>
    
    Write-Host "Attempting to grant Reader access to all subscriptions..."
    $currentUser = (Get-AzContext).Account.Id
    $subscriptions = Get-AzSubscription
    
    Write-Host "Found $($subscriptions.Count) subscriptions. Current user: $currentUser"
    
    foreach ($sub in $subscriptions) {
        Write-Host "Processing subscription: $($sub.Name) ($($sub.Id))"
        
        # Grant Reader role
        try {
            New-AzRoleAssignment -SignInName $currentUser -RoleDefinitionName "Reader" -Scope "/subscriptions/$($sub.Id)" -ErrorAction Stop
            Write-Host "  ✓ Granted Reader role" -ForegroundColor Green
        }
        catch {
            if ($_.Exception.Message -like "*already exists*") {
                Write-Host "  ℹ Already has Reader role" -ForegroundColor Yellow
            } else {
                Write-Host "  ✗ Failed to grant Reader role: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        # Grant Resource Graph Reader role
        try {
            New-AzRoleAssignment -SignInName $currentUser -RoleDefinitionName "Resource Graph Reader" -Scope "/subscriptions/$($sub.Id)" -ErrorAction Stop
            Write-Host "  ✓ Granted Resource Graph Reader role" -ForegroundColor Green
        }
        catch {
            if ($_.Exception.Message -like "*already exists*") {
                Write-Host "  ℹ Already has Resource Graph Reader role" -ForegroundColor Yellow
            } else {
                Write-Host "  ✗ Failed to grant Resource Graph Reader role: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    
    Write-Host "Role assignment process complete. You may need to wait a few minutes for permissions to propagate."
}

function Test-SubscriptionAccess {
    <#
    .SYNOPSIS
    Test if the current user has Resource Graph read access to a subscription
    
    .PARAMETER SubscriptionId
    The subscription ID to test
    #>
    param(
        [string]$SubscriptionId
    )
    
    try {
        # Try a simple Resource Graph query to test access
        $testQuery = "resources | limit 1"
        Search-AzGraph -Query $testQuery -First 1 -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Get-AsmcSitesWithRestrictedAccess {
    <#
    .SYNOPSIS
    Scenario 1: Find App Service sites that are not publicly accessible and use ASMC
    
    .DESCRIPTION
    Identifies App Service sites using App Service Managed Certificates (ASMC) with
    restricted public access (publicNetworkAccess disabled or client certificates enabled).
    
    .PARAMETER SubscriptionId
    Optional subscription ID to target the query
    #>
    param(
        [string]$SubscriptionId
    )
    
    Write-Host "Executing Scenario 1: App Service sites with restricted access using ASMC"
    
    $kqlScenario1 = @"
// ARG Query: Identify App Service sites that commonly restrict public access and use ASMC for custom hostname SSL bindings 
resources 
| where type == "microsoft.web/sites" 
// Extract relevant properties for public access and client certificate settings 
| extend  
    publicNetworkAccess = tolower(tostring(properties.publicNetworkAccess)), 
    clientCertEnabled = tolower(tostring(properties.clientCertEnabled)) 
// Filter for sites that either have public network access disabled  
// or have client certificates enabled (both can restrict public access) 
| where publicNetworkAccess == "disabled"  
    or clientCertEnabled == "true" 
// Expand the list of SSL bindings for each site 
| mv-expand hostNameSslState = properties.hostNameSslStates 
| extend  
    hostName = tostring(hostNameSslState.name), 
    thumbprint = tostring(hostNameSslState.thumbprint) 
// Only consider custom domains (exclude default *.azurewebsites.net) and sites with an SSL certificate bound 
| where tolower(hostName) !endswith "azurewebsites.net" and isnotempty(thumbprint) 
// Select key site properties for output 
| project siteName = name, siteId = id, siteResourceGroup = resourceGroup, thumbprint, publicNetworkAccess, clientCertEnabled 
// Join with certificates to find only those using App Service Managed Certificates (ASMC) 
// ASMCs are identified by the presence of the "canonicalName" property 
| join kind=inner ( 
    resources 
    | where type == "microsoft.web/certificates" 
    | extend  
        certThumbprint = tostring(properties.thumbprint), 
        canonicalName = tostring(properties.canonicalName) 
    | where isnotempty(canonicalName) 
    | project certName = name, certId = id, certResourceGroup = resourceGroup, certExpiration = properties.expirationDate, certThumbprint, canonicalName 
) on `$left.thumbprint == `$right.certThumbprint 
// Final output: sites with restricted public access and using ASMC for custom hostname SSL bindings 
| project siteName, siteId, siteResourceGroup, publicNetworkAccess, clientCertEnabled, thumbprint, certName, certId, certResourceGroup, certExpiration, canonicalName
"@

    $allResults = @()
    
    if ($SubscriptionId) {
        # Single subscription query
        $sub = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
        if ($sub) {
            Write-Host "  Target subscription: $($sub.Name) ($($sub.SubscriptionId))"
            Write-Host "  Tenant: $($sub.TenantId)"
            Write-Host "  Executing Resource Graph query..."
            
            try {
                $results = Search-AzGraph -Query $kqlScenario1 -First 1000 -Subscription $SubscriptionId -ErrorAction Stop
                Write-Host "  Found $($results.Count) matching sites"
                $allResults += $results
            }
            catch {
                Write-Warning "  Failed to query subscription $($sub.Name): $_"
            }
        }
    } else {
        # Multi-subscription query - process each subscription individually
        $subscriptions = Get-AzSubscription -ErrorAction Stop
        Write-Host "  Found $($subscriptions.Count) accessible subscriptions"
        Write-Host "  Testing Resource Graph access for each subscription..."
        
        $accessibleSubs = @()
        foreach ($sub in $subscriptions) {
            Write-Host "    Testing: $($sub.Name) ($($sub.SubscriptionId))"
            if (Test-SubscriptionAccess -SubscriptionId $sub.SubscriptionId) {
                Write-Host "      ✓ Access granted"
                $accessibleSubs += $sub
            } else {
                Write-Host "      ✗ Access denied - skipping"
            }
        }
        
        Write-Host "  Processing $($accessibleSubs.Count) accessible subscriptions:"
        
        foreach ($sub in $accessibleSubs) {
            Write-Host "    Processing: $($sub.Name) ($($sub.SubscriptionId))"
            Write-Host "      Tenant: $($sub.TenantId)"
            
            try {
                $results = Search-AzGraph -Query $kqlScenario1 -First 1000 -Subscription $sub.SubscriptionId -ErrorAction Stop
                Write-Host "      Found $($results.Count) matching sites"
                if ($results.Count -gt 0) {
                    $allResults += $results
                }
            }
            catch {
                Write-Warning "      Failed to query subscription $($sub.Name): $_"
            }
        }
    }
    
    Write-Host "  Total matching sites found across all subscriptions: $($allResults.Count)"
    return $allResults
}

function Get-NonAzureTrafficManagerEndpoints {
    <#
    .SYNOPSIS
    Scenario 2: Find Azure Traffic Manager 'nested' or 'external' endpoints
    
    .DESCRIPTION
    Finds Traffic Manager endpoints that are not "azureEndpoints" type using Azure Resource Graph query.
    This identifies external and nested endpoints that might need special attention.
    
    .PARAMETER SubscriptionId
    Optional subscription ID to target the query
    #>
    param(
        [string]$SubscriptionId
    )
    
    Write-Host "Executing Scenario 2: Finding Traffic Manager non-Azure endpoints"
    
    $kqlScenario2 = @"
// ARG Query: Find all Traffic Manager Endpoints whose type is not "azureEndpoints"
// This identifies external and nested endpoints that might need special configuration attention
resources
| where type == "microsoft.network/trafficmanagerprofiles"
// Expand the endpoints array to get individual endpoint details
| mv-expand endpoint = properties.endpoints
| extend 
    endpointName = tostring(endpoint.name),
    endpointType = tostring(endpoint.type),
    target = tostring(endpoint.properties.target),
    endpointStatus = tostring(endpoint.properties.endpointStatus)
// Filter for non-Azure endpoints (external and nested endpoints)
| where endpointType != "Microsoft.Network/trafficManagerProfiles/azureEndpoints"
// Project the relevant information
| project 
    subscriptionId,
    resourceGroup,
    profileName = name,
    endpointName,
    endpointType,
    target,
    endpointStatus,
    location
"@

    $allResults = @()
    
    if ($SubscriptionId) {
        # Single subscription query
        Write-Host "  Querying subscription: $SubscriptionId"
        try {
            $results = Search-AzGraph -Query $kqlScenario2 -First 1000 -Subscription $SubscriptionId -ErrorAction Stop
            Write-Host "  Found $($results.Count) non-Azure Traffic Manager endpoints"
            if ($results) {
                $allResults += $results
            }
        }
        catch {
            Write-Warning "  Failed to query subscription $SubscriptionId`: $_"
        }
    } else {
        # Multi-subscription query - process each subscription individually
        $subscriptions = Get-AzSubscription -ErrorAction Stop
        Write-Host "  Found $($subscriptions.Count) accessible subscriptions"
        Write-Host "  Testing Resource Graph access for each subscription..."
        
        $accessibleSubs = @()
        foreach ($sub in $subscriptions) {
            Write-Host "    Testing: $($sub.Name) ($($sub.SubscriptionId))"
            if (Test-SubscriptionAccess -SubscriptionId $sub.SubscriptionId) {
                Write-Host "      ✓ Access granted"
                $accessibleSubs += $sub
            } else {
                Write-Host "      ✗ Access denied - skipping"
            }
        }
        
        Write-Host "  Processing $($accessibleSubs.Count) accessible subscriptions:"
        
        foreach ($sub in $accessibleSubs) {
            Write-Host "    $($sub.Name) ($($sub.SubscriptionId))"
            Write-Host "      Tenant: $($sub.TenantId)"
            try {
                $results = Search-AzGraph -Query $kqlScenario2 -First 1000 -Subscription $sub.SubscriptionId -ErrorAction Stop
                if ($results -and $results.Count -gt 0) {
                    Write-Host "      Found $($results.Count) non-Azure Traffic Manager endpoint(s)"
                    $allResults += $results
                } else {
                    Write-Host "      No non-Azure Traffic Manager endpoints found"
                }
            }
            catch {
                Write-Warning "  Failed to query subscription $($sub.Name): $_"
            }
        }
    }
    
    Write-Host "  Total non-Azure Traffic Manager endpoints found: $($allResults.Count)"
    return $allResults
}

function Get-AsmcSitesWithTrafficManagerCname {
    <#
    .SYNOPSIS
    Scenario 3: Find sites relying on *.trafficmanager.net CNAME for custom domain validation
    
    .DESCRIPTION
    Identifies App Service sites using App Service Managed Certificates that rely on 
    *.trafficmanager.net CNAME for custom domain validation.
    
    .PARAMETER SubscriptionId
    Optional subscription ID to target the query
    #>
    param(
        [string]$SubscriptionId
    )
    
    Write-Host "Executing Scenario 3: Sites relying on *.trafficmanager.net CNAME"
    
    $kqlScenario3 = @"
// ARG Query: Identify App Service Managed Certificates (ASMC) issued to *.trafficmanager.net domains 
// Also checks if any web apps are currently using those certificates for custom domain SSL bindings 
resources 
| where type == "microsoft.web/certificates" 
// Extract the certificate thumbprint and canonicalName (ASMCs have a canonicalName property) 
| extend  
    certThumbprint = tostring(properties.thumbprint), 
    canonicalName = tostring(properties.canonicalName) // Only ASMC uses the "canonicalName" property 
// Filter for certificates issued to *.trafficmanager.net domains 
| where canonicalName endswith "trafficmanager.net" 
// Select key certificate properties for output 
| project certName = name, certId = id, certResourceGroup = tostring(properties.resourceGroup), certExpiration = properties.expirationDate, certThumbprint, canonicalName 
// Join with web apps to see if any are using these certificates for SSL bindings 
| join kind=leftouter ( 
    resources 
    | where type == "microsoft.web/sites" 
    // Expand the list of SSL bindings for each site 
    | mv-expand hostNameSslState = properties.hostNameSslStates 
    | extend  
        hostName = tostring(hostNameSslState.name), 
        thumbprint = tostring(hostNameSslState.thumbprint) 
    // Only consider bindings for *.trafficmanager.net custom domains with a certificate bound 
    | where tolower(hostName) endswith "trafficmanager.net" and isnotempty(thumbprint) 
    // Select key site properties for output 
    | project siteName = name, siteId = id, siteResourceGroup = resourceGroup, thumbprint 
) on `$left.certThumbprint == `$right.thumbprint 
// Final output: ASMCs for *.trafficmanager.net domains and any web apps using them 
| project certName, certId, certResourceGroup, certExpiration, canonicalName, siteName, siteId, siteResourceGroup
"@

    $allResults = @()
    
    if ($SubscriptionId) {
        # Single subscription query
        $sub = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
        if ($sub) {
            Write-Host "  Target subscription: $($sub.Name) ($($sub.SubscriptionId))"
            Write-Host "  Tenant: $($sub.TenantId)"
            Write-Host "  Executing Resource Graph query..."
            
            try {
                $results = Search-AzGraph -Query $kqlScenario3 -First 1000 -Subscription $SubscriptionId -ErrorAction Stop
                Write-Host "  Found $($results.Count) matching sites"
                $allResults += $results
            }
            catch {
                Write-Warning "  Failed to query subscription $($sub.Name): $_"
            }
        }
    } else {
        # Multi-subscription query - process each subscription individually
        $subscriptions = Get-AzSubscription -ErrorAction Stop
        Write-Host "  Found $($subscriptions.Count) accessible subscriptions"
        Write-Host "  Testing Resource Graph access for each subscription..."
        
        $accessibleSubs = @()
        foreach ($sub in $subscriptions) {
            Write-Host "    Testing: $($sub.Name) ($($sub.SubscriptionId))"
            if (Test-SubscriptionAccess -SubscriptionId $sub.SubscriptionId) {
                Write-Host "      ✓ Access granted"
                $accessibleSubs += $sub
            } else {
                Write-Host "      ✗ Access denied - skipping"
            }
        }
        
        Write-Host "  Processing $($accessibleSubs.Count) accessible subscriptions:"
        
        foreach ($sub in $accessibleSubs) {
            Write-Host "    Processing: $($sub.Name) ($($sub.SubscriptionId))"
            Write-Host "      Tenant: $($sub.TenantId)"
            
            try {
                $results = Search-AzGraph -Query $kqlScenario3 -First 1000 -Subscription $sub.SubscriptionId -ErrorAction Stop
                Write-Host "      Found $($results.Count) matching sites"
                if ($results.Count -gt 0) {
                    $allResults += $results
                }
            }
            catch {
                Write-Warning "      Failed to query subscription $($sub.Name): $_"
            }
        }
    }
    
    Write-Host "  Total matching sites found across all subscriptions: $($allResults.Count)"
    return $allResults
}

function Export-Results {
    <#
    .SYNOPSIS
    Export results to CSV, JSON, or pipeline based on OutputPath parameter
    
    .PARAMETER Results
    The results object to export
    
    .PARAMETER OutputPath
    Path for CSV export, '-' for JSON to stdout, empty for pipeline output
    
    .PARAMETER ScenarioName
    Name of the scenario for logging purposes
    #>
    param(
        [object]$Results,
        [string]$OutputPath,
        [string]$ScenarioName = "Results"
    )
    
    if ($PSBoundParameters.ContainsKey('OutputPath') -and $OutputPath) {
        if ($OutputPath -eq '-') {
            if ($Results) {
                $Results | ConvertTo-Json -Depth 5 | Write-Output
            } else {
                '[]' | Write-Output  # Empty JSON array for no results
            }
        }
        else {
            try {
                if ($Results -and $Results.Count -gt 0) {
                    $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Force
                    Write-Host "Wrote $ScenarioName to $OutputPath"
                } else {
                    # Create empty CSV with just headers or a message
                    "No results found" | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
                    Write-Host "Wrote $ScenarioName to $OutputPath (no results found)"
                }
            }
            catch {
                Write-Error "Failed to write CSV to $OutputPath : $_"
                throw
            }
        }
    }
    else {
        if ($Results) {
            $Results | Write-Output
        }
        # Return nothing if no results, rather than null
    }
}

function Write-ScenarioReport {
    <#
    .SYNOPSIS
    Write formatted report for each scenario
    
    .PARAMETER ScenarioNumber
    The scenario number (1, 2, or 3)
    
    .PARAMETER ScenarioTitle
    The scenario title/description
    
    .PARAMETER Results
    The results to report on
    
    .PARAMETER NoResultsMessage
    Message to display when no results found
    
    .PARAMETER HasResultsMessage
    Message template to display when results found (use {0} for count placeholder)
    #>
    param(
        [int]$ScenarioNumber,
        [string]$ScenarioTitle,
        [object]$Results,
        [string]$NoResultsMessage,
        [string]$HasResultsMessage
    )
    
    $singleSeparator = ("-" * 50)
    Write-Output $singleSeparator
    Write-Host "Scenario $ScenarioNumber`: $ScenarioTitle"
    
    if ($Results -is [array]) {
        $resultCount = $Results.Count
    }
    elseif ($null -eq $Results) {
        $resultCount = 0
    }
    else {
        $resultCount = 1
    }
    
    if ($resultCount -eq 0) {
        Write-Output $NoResultsMessage
    }
    else {
        Write-Output ($HasResultsMessage -f $resultCount)
        if ($Results -is [array] -and $Results[0].PSObject.Properties.Name -contains 'SubscriptionId') {
            $Results | Format-Table -AutoSize
        }
    }
    Write-Output $singleSeparator
}

# Ensure required modules
Install-ModuleIfMissing -Name Az.Accounts
Install-ModuleIfMissing -Name Az.ResourceGraph
Install-ModuleIfMissing -Name Az.TrafficManager

# Authenticate once
try {
    $context = Get-AzContext -ErrorAction SilentlyContinue
} catch {
    $context = $null
}

if (-not $context -or -not $context.Account) {
    Write-Host "No active Azure session found. Authenticating..."
    if ($UseDeviceLogin) {
        if ($TenantId) { 
            Write-Host "Using device authentication with tenant $TenantId"
            Connect-AzAccount -Tenant $TenantId -UseDeviceAuthentication -Scope "https://management.azure.com/.default" | Out-Null 
        }
        else { 
            Write-Host "Using device authentication"
            Connect-AzAccount -UseDeviceAuthentication -Scope "https://management.azure.com/.default" | Out-Null 
        }
    }
    else {
        if ($TenantId) { 
            Write-Host "Authenticating with tenant $TenantId"
            Connect-AzAccount -Tenant $TenantId -Scope "https://management.azure.com/.default" | Out-Null 
        }
        else { 
            Write-Host "Authenticating interactively"
            Connect-AzAccount -Scope "https://management.azure.com/.default" | Out-Null 
        }
    }
} else {
    Write-Host "Using existing Azure session: $($context.Account.Id)"
    # Refresh token to ensure we have latest permissions
    try {
        $null = Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop
    } catch {
        Write-Warning "Failed to refresh access token. You may need to re-authenticate."
    }
}

# Grant Reader access if requested
if ($GrantReaderAccess) {
    Grant-ReaderAccessToAllSubscriptions
    Write-Host "Waiting 30 seconds for permissions to propagate..." -ForegroundColor Yellow
    Start-Sleep -Seconds 30
}

# Execute all scenarios
Write-Host "Executing ASMC Discovery Report..."

# Scenario 1: Sites with restricted public access using ASMC
$resultsScenario1 = Get-AsmcSitesWithRestrictedAccess

# Scenario 2: Non-Azure Traffic Manager endpoints
$endPointInfo = Get-NonAzureTrafficManagerEndpoints

# Scenario 3: Sites relying on *.trafficmanager.net CNAME
$resultsScenario3 = Get-AsmcSitesWithTrafficManagerCname

# Export results (only export Scenario 1 results to maintain backward compatibility)
Export-Results -Results $resultsScenario1 -OutputPath $OutputPath -ScenarioName "Scenario 1 Results"

# Generate summary report
$doubleSeparator = ("=" * 50)
Write-Output $doubleSeparator
Write-Host "=== ASMC Discovery Report Summary ==="
Write-Output $doubleSeparator

# https://learn.microsoft.com/en-us/azure/app-service/app-service-managed-certificate-changes-july-2025#scenario-1-site-is-not-publicly-accessible
Write-ScenarioReport -ScenarioNumber 1 -ScenarioTitle "Site is not publicly accessible" -Results $resultsScenario1 -NoResultsMessage "No App Service sites found with App Service Managed Certificates and restricted public access or client certificate authentication." -HasResultsMessage "Found {0} App Service sites with App Service Managed Certificates and restricted public access or client certificate authentication."

# https://learn.microsoft.com/en-us/azure/app-service/app-service-managed-certificate-changes-july-2025#scenario-2-site-is-an-azure-traffic-manager-nested-or-external-endpoint
Write-ScenarioReport -ScenarioNumber 2 -ScenarioTitle "Site is an Azure Traffic Manager 'nested' or 'external' endpoint" -Results $endPointInfo -NoResultsMessage "No non-Azure Traffic Manager endpoints found." -HasResultsMessage "Found {0} non-Azure Traffic Manager endpoints."

# https://learn.microsoft.com/en-us/azure/app-service/app-service-managed-certificate-changes-july-2025#scenario-3-site-relies-on-trafficmanager-net-cname-for-custom-domain-validation  
Write-ScenarioReport -ScenarioNumber 3 -ScenarioTitle "Site relies on *.trafficmanager.net CNAME for custom domain validation" -Results $resultsScenario3 -NoResultsMessage "No App Service sites found with App Service Managed Certificates and relying on *.trafficmanager.net CNAME for custom domain validation." -HasResultsMessage "Found {0} App Service sites with App Service Managed Certificates and relying on *.trafficmanager.net CNAME for custom domain validation."
