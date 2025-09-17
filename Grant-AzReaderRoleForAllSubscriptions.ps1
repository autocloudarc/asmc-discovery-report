# Get all subscriptions and grant Reader role to yourself
$userPrincipalName = (Get-AzContext).Account.Id
$subscriptions = Get-AzSubscription

foreach ($sub in $subscriptions) {
    Write-Host "Granting Reader role for subscription: $($sub.Name)"
    try {
        New-AzRoleAssignment -SignInName $userPrincipalName -RoleDefinitionName "Reader" -Scope "/subscriptions/$($sub.Id)" -ErrorAction Stop
        Write-Host "  ✓ Success" -ForegroundColor Green
    }
    catch {
        if ($_.Exception.Message -like "*already exists*") {
            Write-Host "  ℹ Already has Reader role" -ForegroundColor Yellow
        } else {
            Write-Host "  ✗ Failed: $_" -ForegroundColor Red
        }
    }
}