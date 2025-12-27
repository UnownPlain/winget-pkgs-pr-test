Write-Host "Setting execution policy to RemoteSigned..." -ForegroundColor Cyan
try {
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
    Write-Host "Execution policy set successfully." -ForegroundColor Green
}
catch {
    Write-Host "Failed to set execution policy: $_" -ForegroundColor Red
    exit 1
}


if (-not (Test-Path -Path $PROFILE)) {
    Write-Host "Creating profile at: $PROFILE" -ForegroundColor Cyan
    New-Item -ItemType File -Path $PROFILE -Force | Out-Null
    Write-Host "Profile created successfully." -ForegroundColor Green
}

$profileContent = 'irm https://raw.githubusercontent.com/UnownPlain/winget-pkgs-pr-test/HEAD/ValidationScript.ps1 | iex'

Write-Host "Setting up profile..." -ForegroundColor Cyan
Set-Content -Path $PROFILE -Value $profileContent
Write-Host "Profile updated successfully." -ForegroundColor Green

Write-Host "`nBootstrap complete! Restart PowerShell for changes to take effect." -ForegroundColor Green
