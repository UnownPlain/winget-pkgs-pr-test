function Initialize-WinGetSettings {
    $settingsPath = "$env:LOCALAPPDATA\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\settings.json"
    
    if (-not (Test-Path $settingsPath)) {
        # Require administrator privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
        if (-not $isAdmin) {
            Write-Error "Initializing WinGet requires administrator privileges. Please run PowerShell as Administrator."
            exit 1
        }

        $settingsUrl = "https://raw.githubusercontent.com/UnownPlain/winget-pkgs-pr-test/HEAD/settings.json"
        $settingsContent = Invoke-WebRequest -Uri $settingsUrl -UseBasicParsing | Select-Object -ExpandProperty Content
        
        # Create directory if it doesn't exist
        $settingsDir = Split-Path $settingsPath -Parent
        if (-not (Test-Path $settingsDir)) {
            New-Item -ItemType Directory -Path $settingsDir -Force | Out-Null
        }

        Set-Content -Path $settingsPath -Value $settingsContent -Encoding UTF8
        winget settings --enable LocalManifestFiles
        winget source update --name winget
    }
}

# The 2 functions below are taken from
# https://github.com/microsoft/winget-pkgs/blob/HEAD/Tools/SandboxTest.ps1

function Get-ARPTable {
    $registry_paths = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    $arpEntries = @(Get-ItemProperty $registry_paths -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and (-not $_.SystemComponent -or $_.SystemComponent -ne 1 ) } |
            Select-Object DisplayName, DisplayVersion, Publisher, @{N = 'ProductCode'; E = { $_.PSChildName } }, @{N = 'Scope'; E = { if ($_.PSDrive.Name -eq 'HKCU') { 'User' } else { 'Machine' } } }, @{N = 'PackageFamilyName'; E = { $null } })

    $appxPackages = Get-AppxPackage -PackageTypeFilter Main
    foreach ($package in $appxPackages) {
        $manifest = ($package | Get-AppxPackageManifest -ErrorAction SilentlyContinue).Package.Properties
        $arpEntries += [PSCustomObject]@{
            DisplayName       = $manifest.DisplayName
            DisplayVersion    = $package.Version
            Publisher         = $manifest.PublisherDisplayName
            ProductCode       = $null
            Scope             = $null
            PackageFamilyName = $package.PackageFamilyName
        }
    }

    return $arpEntries
}
 
function Update-EnvironmentVariables {
    foreach ($level in "Machine", "User") {
        [Environment]::GetEnvironmentVariables($level).GetEnumerator() | ForEach-Object {
            # For Path variables, append the new values, if they're not already in there
            if ($_.Name -match '^Path$') {
                $_.Value = ($((Get-Content "Env:$($_.Name)") + ";$($_.Value)") -split ';' | Select-Object -Unique) -join ';'
            }
            $_
        } | Set-Content -Path { "Env:$($_.Name)" }
    }
}

function Get-PRFiles {
    param(
        [Parameter(Mandatory = $true)]
        [int]$PRNumber
    )
    
    $apiUrl = "https://api.github.com/repos/microsoft/winget-pkgs/pulls/$PRNumber/files"
    
    Write-Host "--> Fetching files from PR #$PRNumber`n" -ForegroundColor Cyan
    
    $headers = @{
        "Accept"     = "application/vnd.github+json"
        "User-Agent" = "WinGet-PR-Test"
    }
    
    $files = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get
    
    # Filter for only 'added', 'modified', and 'renamed' YAML files, in manifests directory
    $filesToDownload = $files | Where-Object { 
        ($_.status -eq 'added' -or $_.status -eq 'modified' -or $_.status -eq 'renamed') -and
        $_.filename -like 'manifests/*' -and
        $_.filename -like '*.yaml'
    }
    
    if ($filesToDownload.Count -eq 0) {
        throw "No manifest YAML files found in PR #$PRNumber"
    }
    
    # Parse PackageID and Version from folder path
    # Example: manifests/b/BiomeJS/Biome/2.1.1 -> BiomeJS.Biome-2.1.1
    # Example: manifests/x/xpipe-io/xpipe/portable/17.0 -> xpipe-io.xpipe.portable-17.0
    $firstFile = $filesToDownload[0].filename
    $pathParts = $firstFile -split '/'

    # Remove 'manifests', first letter, and filename
    $manifestParts = $pathParts[2..($pathParts.Length - 2)]
    $version = $manifestParts[-1]
    $packageId = ($manifestParts[0..($manifestParts.Length - 2)]) -join '.'
    
    # Generate 5-character UUID
    $uuid = -join ((1..5) | ForEach-Object { Get-Random -InputObject ([char[]]"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") })
    
    $folderName = "$packageId-$version-$uuid"
    $tempFolder = Join-Path $env:TEMP $folderName
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null
    
    Write-Host "--> Downloading files to $tempFolder" -ForegroundColor Yellow
    
    foreach ($file in $filesToDownload) {
        $rawUrl = $file.raw_url
        $filename = Split-Path -Path $file.filename -Leaf
        $outPath = Join-Path $tempFolder $filename

        Write-Host "- Downloading: $filename" -ForegroundColor Gray
        Invoke-WebRequest -Uri $rawUrl -OutFile $outPath -Headers $headers
    }
    
    return $tempFolder
}

function PRTest {
    param(
        [Parameter(Mandatory = $true)]
        [int]$PRNumber
    )
    
    try {
        Initialize-WinGetSettings
        
        # Get ARP table before installation
        $originalARP = Get-ARPTable
        
        $manifestPath = Get-PRFiles -PRNumber $PRNumber
        
        Write-Host "`n--> Running winget install`n" -ForegroundColor Green
        winget install -m $manifestPath --accept-source-agreements --accept-package-agreements
        
        Write-Host "`n--> Updating environment variables..." -NoNewline -ForegroundColor Cyan
        Update-EnvironmentVariables
        
        # Get ARP table after installation and compare
        $newARP = Get-ARPTable
        $arpDiff = Compare-Object -ReferenceObject $originalARP -DifferenceObject $newARP -Property DisplayName, DisplayVersion, Publisher, ProductCode, PackageFamilyName, Scope -PassThru
        
        Write-Host "`n--> Installed Packages:`n" -ForegroundColor Cyan
        
        if ($arpDiff) {
            $arpDiff | Where-Object { $_.SideIndicator -eq '=>' } |
                Select-Object DisplayName, DisplayVersion, Publisher, ProductCode, PackageFamilyName, Scope |
                ForEach-Object {
                    $hash = [ordered]@{}
                    $_.PSObject.Properties | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Value) } |
                        ForEach-Object { $hash[$_.Name] = $_.Value }
                        [PSCustomObject]$hash
                    } | Format-List | Out-String | ForEach-Object { $_.Trim() }
        }
        else {
            Write-Host "No changes detected in ARP table." -ForegroundColor Yellow
        }

        Write-Host
    }
    catch {
        Write-Error "Error: $_"
    }
}
