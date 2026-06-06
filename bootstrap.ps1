#Requires -Version 5.1
#Requires -RunAsAdministrator

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    "PSAvoidUsingWriteHost",
    ""
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    "PSUseShouldProcessForStateChangingFunctions",
    ""
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    "PSUseSingularNouns",
    ""
)]
param()

$isAdmin = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    throw 'Initializing the VM requires an elevated Windows PowerShell session.'
}

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Set-RegistryPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [ValidateSet('DWord', 'String')]
        [string]$Type
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

function Set-EdgeDebloatPolicies {
    $edgeDebloatPolicies = @(
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'; Name = 'CreateDesktopShortcutDefault'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'; Name = 'UpdateDefault'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'; Name = 'AutoUpdateCheckPeriodMinutes'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'PersonalizationReportingEnabled'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist'; Name = '1'; Value = 'ofefcgjbeghpigppfmkologfjadafddi'; Type = 'String' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'ShowRecommendationsEnabled'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'HideFirstRunExperience'; Value = 1; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'UserFeedbackAllowed'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'ConfigureDoNotTrack'; Value = 1; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'AlternateErrorPagesEnabled'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'EdgeCollectionsEnabled'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'EdgeShoppingAssistantEnabled'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'MicrosoftEdgeInsiderPromotionEnabled'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'ShowMicrosoftRewards'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'WebWidgetAllowed'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'DiagnosticData'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'EdgeAssetDeliveryServiceEnabled'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'WalletDonationEnabled'; Value = 0; Type = 'DWord' },
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name = 'DefaultBrowserSettingsCampaignEnabled'; Value = 0; Type = 'DWord' }
    )

    Write-Host "Applying Microsoft Edge debloat and update policies..." -ForegroundColor Cyan
    foreach ($policy in $edgeDebloatPolicies) {
        Set-RegistryPolicy @policy
    }
    Write-Host "Microsoft Edge policies applied successfully." -ForegroundColor Green
}

function Invoke-CurlDownload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$OutFile
    )

    & curl.exe --fail --silent --show-error --location --output $OutFile $Uri

    if ($LASTEXITCODE -ne 0) {
        throw "curl.exe failed to download $Uri (exit code $LASTEXITCODE)"
    }
}

function Initialize-WinGetSettings {
    $settingsPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\settings.json'

    if (Test-Path -LiteralPath $settingsPath) {
        return
    }

    $settingsUrl = 'https://raw.githubusercontent.com/UnownPlain/winget-pkgs-pr-test/HEAD/settings.json'
    $settingsDirectory = Split-Path -Path $settingsPath -Parent

    if (-not (Test-Path -LiteralPath $settingsDirectory)) {
        New-Item -ItemType Directory -Path $settingsDirectory -Force | Out-Null
    }

    Invoke-CurlDownload -Uri $settingsUrl -OutFile $settingsPath
    Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe

    winget settings --enable LocalManifestFiles
    winget source update --name winget
}

function Add-DirectoryToMachinePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $pathParts = @($machinePath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    if ($pathParts -notcontains $Path) {
        $updatedPath = ($pathParts + $Path) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $updatedPath, 'Machine')
    }

    $currentPathParts = @($env:Path -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($currentPathParts -notcontains $Path) {
        $env:Path = ($currentPathParts + $Path) -join ';'
    }
}

function Install-AnthelionKomac {
    $architecture = switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'x86_64'; break }
        'ARM64' { 'aarch64'; break }
        default { throw "Unsupported processor architecture: $env:PROCESSOR_ARCHITECTURE" }
    }

    $installDirectory = Join-Path -Path $env:ProgramData -ChildPath 'ath'
    $athPath = Join-Path -Path $installDirectory -ChildPath 'ath.exe'
    $downloadUrl = "https://github.com/unpn-org/Komac/releases/download/nightly/komac-nightly-$architecture-pc-windows-msvc.exe"

    Write-Host "Installing ath.exe ($architecture)..." -ForegroundColor Cyan

    if (-not (Test-Path -LiteralPath $installDirectory)) {
        New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null
    }

    Invoke-CurlDownload -Uri $downloadUrl -OutFile $athPath
    Add-DirectoryToMachinePath -Path $installDirectory

    Write-Host "ath.exe installed successfully." -ForegroundColor Green
}

function Set-DefaultWindowsWallpaper {
    $wallpaperPath = Join-Path -Path $env:SystemRoot -ChildPath 'Web\Wallpaper\Windows\img0.jpg'

    Set-RegistryPolicy -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsSpotlightFeatures' -Value 1 -Type 'DWord'

    if (-not (Test-Path -LiteralPath $wallpaperPath)) {
        Write-Host "Windows default wallpaper not found at $wallpaperPath. Skipping wallpaper setup." -ForegroundColor Yellow
        return
    }

    Write-Host "Setting desktop and lock screen wallpaper..." -ForegroundColor Cyan

    Set-RegistryPolicy -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'LockScreenImage' -Value $wallpaperPath -Type 'String'

    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'Wallpaper' -Value $wallpaperPath
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'WallpaperStyle' -Value '10'
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'TileWallpaper' -Value '0'

    Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;

public static class Wallpaper {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SystemParametersInfo(int uiAction, int uiParam, string pvParam, int fWinIni);
}
'@

    [Wallpaper]::SystemParametersInfo(20, 0, $wallpaperPath, 3) | Out-Null

    Write-Host "Desktop and lock screen wallpaper set successfully." -ForegroundColor Green
}

Write-Host "Setting execution policy to RemoteSigned..." -ForegroundColor Cyan
try {
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction Stop
    Write-Host "Execution policy set successfully." -ForegroundColor Green
}
catch {
    $currentUserPolicy = Get-ExecutionPolicy -Scope CurrentUser
    $effectivePolicy = Get-ExecutionPolicy
    $usablePolicies = @('RemoteSigned', 'Unrestricted', 'Bypass')

    if ($currentUserPolicy -eq 'RemoteSigned' -and $effectivePolicy -in $usablePolicies) {
        Write-Host "Execution policy was set for CurrentUser; the effective policy remains $effectivePolicy due to a more specific scope." -ForegroundColor Yellow
    }
    else {
        Write-Host "Failed to set execution policy: $_" -ForegroundColor Red
        exit 1
    }
}

Initialize-WinGetSettings
Set-EdgeDebloatPolicies
Install-AnthelionKomac
Set-DefaultWindowsWallpaper


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
