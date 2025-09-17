# Debug script to test ASMC queries
Write-Output "=== ASMC Debug Test ==="

# Test 1: Basic App Service count
Write-Output "`n1. Testing basic App Service site count..."
$basicQuery = "resources | where type == 'microsoft.web/sites' | count"
try {
    $basicCount = Search-AzGraph -Query $basicQuery
    Write-Output "Total App Service sites: $($basicCount.Count_)"
} catch {
    Write-Output "Basic query failed: $_"
}

# Test 2: Sites with restricted access
Write-Output "`n2. Testing sites with restricted access..."
$restrictedQuery = @"
resources
| where type == "microsoft.web/sites"
| extend  
    publicNetworkAccess = tolower(tostring(properties.publicNetworkAccess)), 
    clientCertEnabled = tolower(tostring(properties.clientCertEnabled))
| where publicNetworkAccess == "disabled" or clientCertEnabled != "false"
| count
"@
try {
    $restrictedCount = Search-AzGraph -Query $restrictedQuery
    Write-Output "Sites with restricted access: $($restrictedCount.Count_)"
} catch {
    Write-Output "Restricted access query failed: $_"
}

# Test 3: ASMC certificates
Write-Output "`n3. Testing ASMC certificates..."
$asmcQuery = @"
resources 
| where type == "microsoft.web/certificates" 
| extend canonicalName = tostring(properties.canonicalName) 
| where isnotempty(canonicalName)
| count
"@
try {
    $asmcCount = Search-AzGraph -Query $asmcQuery
    Write-Output "ASMC certificates: $($asmcCount.Count_)"
} catch {
    Write-Output "ASMC query failed: $_"
}

# Test 4: Traffic Manager profiles
Write-Output "`n4. Testing Traffic Manager profiles..."
$tmQuery = "resources | where type == 'microsoft.network/trafficmanagerprofiles' | count"
try {
    $tmCount = Search-AzGraph -Query $tmQuery
    Write-Output "Traffic Manager profiles: $($tmCount.Count_)"
} catch {
    Write-Output "TM query failed: $_"
}

Write-Output "`n=== Debug Complete ==="