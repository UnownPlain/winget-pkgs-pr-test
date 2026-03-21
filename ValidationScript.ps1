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

function Expand-OneLevelArray {
    param(
        [object[]]$Items
    )

    $expanded = @()

    foreach ($item in $Items) {
        if ($null -eq $item) {
            continue
        }

        if ($item -is [System.Array]) {
            $expanded += @($item | Where-Object { $null -ne $_ })
        }
        else {
            $expanded += $item
        }
    }

    return $expanded
}

function Initialize-WinGetSettings {
    $ProgressPreference = 'SilentlyContinue'
    $settingsPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\settings.json'

    if (-not (Test-Path -LiteralPath $settingsPath)) {
        # Require administrator privileges
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
        if (-not $isAdmin) {
            Write-Error "Initializing WinGet requires administrator privileges. Please run PowerShell as Administrator."
            exit 1
        }

        $settingsUrl = "https://raw.githubusercontent.com/UnownPlain/winget-pkgs-pr-test/HEAD/settings.json"
        $settingsContent = Invoke-WebRequest -Uri $settingsUrl -UseBasicParsing | Select-Object -ExpandProperty Content

        # Create directory if it doesn't exist
        $settingsDir = Split-Path $settingsPath -Parent
        if (-not (Test-Path -LiteralPath $settingsDir)) {
            New-Item -ItemType Directory -Path $settingsDir -Force | Out-Null
        }

        Set-Content -LiteralPath $settingsPath -Value $settingsContent -Encoding UTF8

        Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe

        winget settings --enable LocalManifestFiles
        winget source update --name winget
    }
}

# The 2 functions below are taken from
# https://github.com/microsoft/winget-pkgs/blob/HEAD/Tools/SandboxTest.ps1

function Get-ARPTable {
    param(
        [string]$DisplayName
    )

    $excludedPackageFamilyNames = @(
        '1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy',
        'c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy',
        'E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy',
        'F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy',
        'Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy',
        'Microsoft.AccountsControl_cw5n1h2txyewy',
        'Microsoft.AsyncTextService_8wekyb3d8bbwe',
        'Microsoft.BioEnrollment_cw5n1h2txyewy',
        'Microsoft.CredDialogHost_cw5n1h2txyewy',
        'Microsoft.ECApp_8wekyb3d8bbwe',
        'Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe',
        'Microsoft.Win32WebViewHost_cw5n1h2txyewy',
        'Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy',
        'Microsoft.Windows.AssignedAccessLockApp_cw5n1h2txyewy',
        'Microsoft.Windows.CapturePicker_cw5n1h2txyewy',
        'Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy',
        'Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy',
        'Microsoft.Windows.ParentalControls_cw5n1h2txyewy',
        'Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy',
        'Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy',
        'Microsoft.Windows.PrintQueueActionCenter_cw5n1h2txyewy',
        'Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy',
        'Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy',
        'Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy',
        'Microsoft.XboxGameCallableUI_cw5n1h2txyewy',
        'MicrosoftWindows.Client.FileExp_cw5n1h2txyewy',
        'MicrosoftWindows.Client.Photon_cw5n1h2txyewy',
        'MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy',
        'Windows.CBSPreview_cw5n1h2txyewy',
        'windows.immersivecontrolpanel_cw5n1h2txyewy',
        'Windows.PrintDialog_cw5n1h2txyewy',
        'Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy',
        'Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy',
        'Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy',
        'MicrosoftWindows.Client.CBS_cw5n1h2txyewy',
        'MicrosoftWindows.Client.Core_cw5n1h2txyewy',
        'MicrosoftWindows.Client.OOBE_cw5n1h2txyewy',
        'Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe',
        'MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe',
        'Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe',
        'Microsoft.Windows.DevHome_8wekyb3d8bbwe',
        'Microsoft.OutlookForWindows_8wekyb3d8bbwe',
        'Microsoft.WebMediaExtensions_8wekyb3d8bbwe',
        'Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe',
        'Microsoft.SecHealthUI_8wekyb3d8bbwe',
        'Microsoft.BingNews_8wekyb3d8bbwe',
        'Microsoft.WindowsCalculator_8wekyb3d8bbwe',
        'Microsoft.HEVCVideoExtension_8wekyb3d8bbwe',
        'Microsoft.ScreenSketch_8wekyb3d8bbwe',
        'MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy',
        'Microsoft.Xbox.TCUI_8wekyb3d8bbwe',
        'Microsoft.WidgetsPlatformRuntime_8wekyb3d8bbwe',
        'Microsoft.XboxIdentityProvider_8wekyb3d8bbwe',
        'Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe',
        'Microsoft.BingWeather_8wekyb3d8bbwe',
        'MicrosoftWindows.57242383.Tasbar_cw5n1h2txyewy',
        'MicrosoftWindows.59336768.Speion_cw5n1h2txyewy',
        'MicrosoftWindows.59337133.Voiess_cw5n1h2txyewy',
        'MicrosoftWindows.59337145.Livtop_cw5n1h2txyewy',
        'MicrosoftWindows.59379618.InpApp_cw5n1h2txyewy',
        'MicrosoftWindows.Client.CoreAI_cw5n1h2txyewy',
        'Microsoft.LockApp_cw5n1h2txyewy',
        'Microsoft.WindowsNotepad_8wekyb3d8bbwe',
        'Microsoft.MPEG2VideoExtension_8wekyb3d8bbwe',
        'Microsoft.WindowsAlarms_8wekyb3d8bbwe',
        'Microsoft.RawImageExtension_8wekyb3d8bbwe',
        'Microsoft.ApplicationCompatibilityEnhancements_8wekyb3d8bbwe',
        'Microsoft.AVCEncoderVideoExtension_8wekyb3d8bbwe',
        'Microsoft.XboxGamingOverlay_8wekyb3d8bbwe',
        'Microsoft.WindowsCamera_8wekyb3d8bbwe',
        'Microsoft.VP9VideoExtensions_8wekyb3d8bbwe',
        'Microsoft.AV1VideoExtension_8wekyb3d8bbwe',
        'Microsoft.WebpImageExtension_8wekyb3d8bbwe',
        'Microsoft.PowerAutomateDesktop_8wekyb3d8bbwe',
        'MicrosoftWindows.CrossDevice_cw5n1h2txyewy',
        'Microsoft.YourPhone_8wekyb3d8bbwe',
        'Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe',
        'Microsoft.Paint_8wekyb3d8bbwe',
        'Microsoft.Windows.Photos_8wekyb3d8bbwe',
        'Microsoft.GamingApp_8wekyb3d8bbwe',
        'Microsoft.GetHelp_8wekyb3d8bbwe',
        'Microsoft.BingSearch_8wekyb3d8bbwe',
        'Microsoft.ZuneMusic_8wekyb3d8bbwe',
        'Microsoft.Todos_8wekyb3d8bbwe',
        'Microsoft.StorePurchaseApp_8wekyb3d8bbwe',
        'Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe',
        'Microsoft.StartExperiencesApp_8wekyb3d8bbwe',
        'Microsoft.HEIFImageExtension_8wekyb3d8bbwe',
        'Clipchamp.Clipchamp_yxz26nhyzhsrt',
        'Microsoft.WindowsStore_8wekyb3d8bbwe',
        'Microsoft.Winget.Source_8wekyb3d8bbwe'
    )

    $registryPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $arpEntries = @(Get-ItemProperty $registryPaths -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and (-not $_.SystemComponent -or $_.SystemComponent -ne 1) } |
            Select-Object DisplayName,
            DisplayVersion,
            Publisher,
            @{N = 'ProductCode'; E = { $_.PSChildName } },
            @{N = 'Scope'; E = { if ($_.PSDrive.Name -eq 'HKCU') { 'User' } else { 'Machine' } } },
            @{N = 'PackageFamilyName'; E = { $null } })

    $appxPackages = Get-AppxPackage -PackageTypeFilter Main
    foreach ($package in $appxPackages) {
        try {
            $manifest = ($package | Get-AppxPackageManifest).Package.Properties
            if ($null -ne $manifest) {
                $arpEntries += [PSCustomObject]@{
                    DisplayName       = $manifest.DisplayName
                    DisplayVersion    = $package.Version
                    Publisher         = $manifest.PublisherDisplayName
                    ProductCode       = $null
                    Scope             = $null
                    PackageFamilyName = $package.PackageFamilyName
                }
            }
        }
        catch {
            # Skip packages that throw errors when getting manifest
            continue
        }
    }

    $filteredEntries = @($arpEntries | Where-Object {
            -not ($excludedPackageFamilyNames -contains $_.PackageFamilyName)
        })

    if (-not [string]::IsNullOrWhiteSpace($DisplayName)) {
        $filteredEntries = @($filteredEntries | Where-Object {
                $_.DisplayName -like "*$DisplayName*"
            })
    }

    return $filteredEntries
}

function Update-EnvironmentVariables {
    foreach ($level in 'Machine', 'User') {
        [Environment]::GetEnvironmentVariables($level).GetEnumerator() | ForEach-Object {
            # For Path variables, append the new values, if they're not already in there
            if ($_.Name -match '^Path$') {
                $existingPath = Get-Content -Path "Env:$($_.Name)"
                $_.Value = (($existingPath + ";$($_.Value)") -split ';' | Select-Object -Unique) -join ';'
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

    $filesApiUrl = "https://api.github.com/repos/microsoft/winget-pkgs/pulls/$PRNumber/files"
    $prApiUrl = "https://api.github.com/repos/microsoft/winget-pkgs/pulls/$PRNumber"

    Write-Host "==> Fetching files from PR #$PRNumber`n" -ForegroundColor Cyan

    $headers = @{
        "Accept"     = "application/vnd.github+json"
        "User-Agent" = "WinGet-PR-Test"
    }

    $files = Expand-OneLevelArray -Items @(Invoke-RestMethod -Uri $filesApiUrl -Headers $headers -Method Get)
    $prInfo = Invoke-RestMethod -Uri $prApiUrl -Headers $headers -Method Get

    $headSha = $prInfo.head.sha
    $headRepoFullName = $prInfo.head.repo.full_name

    # Filter for only 'added', 'modified', and 'renamed' YAML files in manifests directory.
    $allowedStatuses = @('added', 'modified', 'renamed')
    $filesToDownload = @($files | Where-Object {
            $_.status -in $allowedStatuses -and
            $_.filename -like 'manifests/*.yaml'
        })

    if ($filesToDownload.Count -eq 0) {
        throw "No manifest YAML files found in PR #$PRNumber"
    }

    # Pick one changed file, move back one directory and fetch any unchanged YAML files there.
    $selectedDirectory = ($filesToDownload[0].filename -split '/' | Select-Object -SkipLast 1) -join "/"
    $directoryApiUrl = "https://api.github.com/repos/$headRepoFullName/contents/${selectedDirectory}?ref=$headSha"
    $directoryContents = Expand-OneLevelArray -Items @(Invoke-RestMethod -Uri $directoryApiUrl -Headers $headers -Method Get)
    $unchangedFilesToDownload = @($directoryContents | Where-Object {
        $null -ne $_ -and
        $_.type -eq 'file' -and
        $_.name -like '*.yaml' -and
        ($filesToDownload.filename -notcontains $_.path)
    })

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

    Write-Host "==> Downloading files to $tempFolder" -ForegroundColor Yellow

    $downloadItems = Expand-OneLevelArray -Items (@($filesToDownload) + @($unchangedFilesToDownload))
    if ($downloadItems.Count -eq 0) {
        throw "No downloadable manifest files could be resolved for PR #$PRNumber."
    }

    $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, [Math]::Min(8, $downloadItems.Count))
    $runspacePool.Open()

    $downloadScript = {
        param($rawUrl, $outPath, $headers, $fileName)

        try {
            $webClient = New-Object System.Net.WebClient
            foreach ($key in $headers.Keys) {
                $webClient.Headers.Add($key, $headers[$key])
            }

            $webClient.DownloadFile($rawUrl, $outPath)

            [PSCustomObject]@{
                File = $fileName
                Path = $outPath
            }
        }
        catch {
            throw "Failed to download $fileName from $rawUrl. $_"
        }
        finally {
            if ($webClient) {
                $webClient.Dispose()
            }
        }
    }

    $skippedEntries = 0
    $downloadTasks = foreach ($file in $downloadItems) {
        $sourcePath = $null

        if ($file.PSObject.Properties.Name -contains 'filename' -and -not [string]::IsNullOrWhiteSpace($file.filename)) {
            $sourcePath = $file.filename
        }
        elseif ($file.PSObject.Properties.Name -contains 'path' -and -not [string]::IsNullOrWhiteSpace($file.path)) {
            $sourcePath = $file.path
        }
        elseif ($file.PSObject.Properties.Name -contains 'name' -and -not [string]::IsNullOrWhiteSpace($file.name)) {
            $sourcePath = "$selectedDirectory/$($file.name)"
        }

        if ([string]::IsNullOrWhiteSpace($sourcePath)) {
            $skippedEntries++
            continue
        }

        $escapedPath = (($sourcePath -split '/') | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/'
        $fallbackRawUrl = "https://raw.githubusercontent.com/$headRepoFullName/$headSha/$escapedPath"
        $rawUrlCandidates = @()
        if ($file.PSObject.Properties.Name -contains 'raw_url') {
            $rawUrlCandidates += $file.raw_url
        }
        if ($file.PSObject.Properties.Name -contains 'download_url') {
            $rawUrlCandidates += $file.download_url
        }
        $rawUrlCandidates += $fallbackRawUrl

        $rawUrl = $rawUrlCandidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
        if ([string]::IsNullOrWhiteSpace($rawUrl)) {
            throw "Unable to determine a download URL for file '$sourcePath'."
        }

        $fileName = Split-Path -Path $sourcePath -Leaf
        $outPath = Join-Path -Path $tempFolder -ChildPath $fileName

        $powerShell = [PowerShell]::Create()
        $powerShell.RunspacePool = $runspacePool

        $null = $powerShell.AddScript($downloadScript.ToString()).AddArgument($rawUrl).AddArgument($outPath).AddArgument($headers).AddArgument($fileName)

        [PSCustomObject]@{
            File = $fileName
            PowerShell = $powerShell
            Handle = $powerShell.BeginInvoke()
        }
    }

    if ($downloadTasks.Count -eq 0) {
        throw "No downloadable manifest files could be resolved for PR #$PRNumber."
    }

    if ($skippedEntries -gt 0) {
        Write-Host "- Skipped $skippedEntries non-file entries from API response" -ForegroundColor DarkYellow
    }

    try {
        foreach ($task in $downloadTasks) {
            $result = $task.PowerShell.EndInvoke($task.Handle)

            if ($result) {
                $result | ForEach-Object {
                    Write-Host "- Downloaded: $($_.File)" -ForegroundColor Gray
                }
            }
        }
    }
    finally {
        foreach ($task in $downloadTasks) {
            if ($task.PowerShell) {
                $task.PowerShell.Dispose()
            }
        }

        $runspacePool.Close()
        $runspacePool.Dispose()
    }

    return $tempFolder
}

function PRTest {
    param(
        [Parameter(Mandatory = $true)]
        [int]$PRNumber,

        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$WingetArgs
    )

    try {
        Initialize-WinGetSettings

        # Get ARP table before installation
        $originalARP = Get-ARPTable

        $manifestPath = Get-PRFiles -PRNumber $PRNumber

        Write-Host "`n==> Running winget install`n" -ForegroundColor Green
        winget install -m $manifestPath --accept-source-agreements --accept-package-agreements @WingetArgs

        Write-Host "`n==> Updating environment variables..." -NoNewline -ForegroundColor Cyan
        Update-EnvironmentVariables

        # Get ARP table after installation and compare
        $newARP = Get-ARPTable
        $arpDiff = Compare-Object -ReferenceObject $originalARP -DifferenceObject $newARP -Property DisplayName, DisplayVersion, Publisher, ProductCode, PackageFamilyName, Scope -PassThru

        Write-Host "`n==> Installed Packages:`n" -ForegroundColor Cyan

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
