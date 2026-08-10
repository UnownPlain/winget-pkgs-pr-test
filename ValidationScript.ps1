#Requires -Version 5.1

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    "PSAvoidUsingWriteHost",
    ""
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    "PSUseShouldProcessForStateChangingFunctions",
    ""
)]
param()

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# The 2 functions below are adapted from
# https://github.com/microsoft/winget-pkgs/blob/HEAD/Tools/SandboxTest.ps1

function Get-ARPTable {
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
            @{N = 'RegistryPath'; E = { $_.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', '' } },
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
                    RegistryPath      = $null
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

    return @($arpEntries | Where-Object {
            -not ($excludedPackageFamilyNames -contains $_.PackageFamilyName)
        })
}

function Get-FontTable {
    $registryLocations = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts'; Scope = 'Machine' },
        @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts'; Scope = 'User' }
    )

    $providerProperties = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')

    foreach ($location in $registryLocations) {
        if (-not (Test-Path -LiteralPath $location.Path)) {
            continue
        }

        $registryKey = Get-ItemProperty -LiteralPath $location.Path
        $registryKey.PSObject.Properties | Where-Object {
            $providerProperties -notcontains $_.Name
        } | ForEach-Object {
            [PSCustomObject]@{
                DisplayName  = $_.Name
                File         = $_.Value
                RegistryPath = $location.Path
                Scope        = $location.Scope
            }
        }
    }
}

function Test-FontManifestPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fontInstallerPattern = '^\s*(?:InstallerType|NestedInstallerType):\s*[''"]?font[''"]?\s*(?:#.*)?$'
    $fontInstaller = Get-ChildItem -LiteralPath $Path -Filter '*.yaml' -File |
        Select-String -Pattern $fontInstallerPattern |
        Select-Object -First 1

    return $null -ne $fontInstaller
}

function Update-ProcessEnvironment {
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

function Invoke-GitHubApi {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $response = & curl.exe --fail --silent --show-error --location `
        --header 'Accept: application/vnd.github+json' `
        --header 'User-Agent: WinGet-PR-Test' `
        $Uri | Out-String

    if ($LASTEXITCODE -ne 0) {
        throw "curl.exe failed to retrieve $Uri (exit code $LASTEXITCODE)"
    }

    return $response | ConvertFrom-Json
}

function Resolve-PRReference {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PullRequest
    )

    $prNumber = 0
    if ([int]::TryParse($PullRequest, [ref]$prNumber)) {
        if ($prNumber -le 0) {
            throw 'The PR number must be greater than zero.'
        }

        return [PSCustomObject]@{
            Repository = 'microsoft/winget-pkgs'
            Number     = $prNumber
            Url        = "https://github.com/microsoft/winget-pkgs/pull/$prNumber"
        }
    }

    $uri = $null
    if (-not [Uri]::TryCreate($PullRequest, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -ne 'https' -or
        $uri.Host -notin 'github.com', 'www.github.com') {
        throw "Invalid PR reference '$PullRequest'. Use a winget-pkgs PR number or a GitHub PR URL."
    }

    $segments = @($uri.AbsolutePath.Trim('/') -split '/')
    if ($segments.Count -lt 4 -or
        $segments[2] -ne 'pull' -or
        -not [int]::TryParse($segments[3], [ref]$prNumber) -or
        $prNumber -le 0) {
        throw "Invalid GitHub PR URL '$PullRequest'. Expected https://github.com/{owner}/{repository}/pull/{number}."
    }

    $repository = "$($segments[0])/$($segments[1])"

    return [PSCustomObject]@{
        Repository = $repository
        Number     = $prNumber
        Url        = "https://github.com/$repository/pull/$prNumber"
    }
}

function Get-PRManifestPath {
    param(
        [Parameter(Mandatory = $true)]
        [Alias('PRNumber')]
        [string]$PullRequest
    )

    $pr = Resolve-PRReference -PullRequest $PullRequest

    Write-Host "==> Fetching files from $($pr.Url)`n" -ForegroundColor Cyan

    $headers = @{
        Accept       = 'application/vnd.github+json'
        'User-Agent' = 'WinGet-PR-Test'
    }

    $apiUrl = "https://api.github.com/repos/$($pr.Repository)/pulls/$($pr.Number)"
    $prInfo = Invoke-GitHubApi -Uri $apiUrl
    $changedFiles = Invoke-GitHubApi -Uri "$apiUrl/files?per_page=100"
    $headSha = $prInfo.head.sha
    $headRepoFullName = $prInfo.head.repo.full_name

    $changedManifest = $changedFiles | Where-Object {
        $_.status -in 'added', 'modified', 'renamed' -and
        $_.filename -match '^(?:manifests|fonts)/.+\.yaml$'
    } | Select-Object -First 1

    if (-not $changedManifest) {
        throw "No package or font manifest YAML files found in $($pr.Url)"
    }

    $manifestDirectory = $changedManifest.filename -replace '/[^/]+$', ''
    $contentsUrl = "https://api.github.com/repos/$headRepoFullName/contents/${manifestDirectory}?ref=$headSha"
    $manifestFiles = @((Invoke-GitHubApi -Uri $contentsUrl) | Where-Object {
            $_.type -eq 'file' -and $_.name -like '*.yaml'
        })

    if ($manifestFiles.Count -eq 0) {
        throw "No manifest YAML files found in $manifestDirectory"
    }

    $tempFolder = Join-Path $env:TEMP "winget-pr-$($pr.Number)-$([guid]::NewGuid().ToString('N').Substring(0, 5))"
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    Write-Host "==> Downloading files to $tempFolder" -ForegroundColor Yellow

    [Net.ServicePointManager]::DefaultConnectionLimit = [Math]::Max(
        [Net.ServicePointManager]::DefaultConnectionLimit,
        $manifestFiles.Count
    )

    $downloads = @()

    try {
        foreach ($file in $manifestFiles) {
            $client = [System.Net.WebClient]::new()
            $download = [PSCustomObject]@{
                Client = $client
                File   = $file.name
                Task   = $null
            }
            $downloads += $download

            foreach ($header in $headers.GetEnumerator()) {
                $client.Headers.Add($header.Key, $header.Value)
            }

            $download.Task = $client.DownloadFileTaskAsync(
                [Uri]$file.download_url,
                (Join-Path -Path $tempFolder -ChildPath $file.name)
            )
        }

        $tasks = [System.Threading.Tasks.Task[]]@($downloads | ForEach-Object { $_.Task })
        [System.Threading.Tasks.Task]::WaitAll($tasks)

        $downloads.File | ForEach-Object {
            Write-Host "- Downloaded: $_" -ForegroundColor Gray
        }
    }
    finally {
        $downloads.Client | ForEach-Object { $_.Dispose() }
    }

    return $tempFolder
}

function PRTest {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias('PRNumber', 'Url')]
        [string]$PullRequest,

        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$WingetArgs
    )

    try {
        $manifestPath = Get-PRManifestPath -PullRequest $PullRequest
        $isFontManifest = Test-FontManifestPath -Path $manifestPath

        if ($isFontManifest) {
            # Fonts do not create ARP entries, so capture the Windows font registry instead.
            $originalFonts = @(Get-FontTable)
        }
        else {
            $originalARP = Get-ARPTable
        }

        Write-Host "`n==> Running winget install`n" -ForegroundColor Green
        winget install -m $manifestPath --accept-source-agreements --accept-package-agreements @WingetArgs

        if ($LASTEXITCODE -ne 0) {
            throw "winget install failed (exit code $LASTEXITCODE)."
        }

        Write-Host "`n==> Updating environment variables..." -NoNewline -ForegroundColor Cyan
        Update-ProcessEnvironment

        if ($isFontManifest) {
            $properties = 'DisplayName', 'File', 'RegistryPath', 'Scope'
            $installedFonts = Compare-Object -ReferenceObject $originalFonts -DifferenceObject @(Get-FontTable) -Property $properties -PassThru |
                Where-Object SideIndicator -EQ '=>'

            Write-Host "`n==> Installed Fonts:`n" -ForegroundColor Cyan

            if ($installedFonts) {
                $installedFonts | Select-Object $properties | Format-List | Out-String | ForEach-Object { $_.Trim() }
            }
            else {
                Write-Host "No changes detected in the Windows font registry." -ForegroundColor Yellow
            }
        }
        else {
            # Get ARP table after installation and compare
            $properties = 'DisplayName', 'DisplayVersion', 'Publisher', 'ProductCode', 'RegistryPath', 'PackageFamilyName', 'Scope'
            $installedPackages = Compare-Object -ReferenceObject $originalARP -DifferenceObject (Get-ARPTable) -Property $properties -PassThru |
                Where-Object SideIndicator -EQ '=>'

            Write-Host "`n==> Installed Packages:`n" -ForegroundColor Cyan

            if ($installedPackages) {
                $installedPackages | Select-Object $properties | ForEach-Object {
                    $package = [ordered]@{}
                    $_.PSObject.Properties | Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_.Value)
                    } | ForEach-Object {
                        $package[$_.Name] = $_.Value
                    }
                    [PSCustomObject]$package
                } | Format-List | Out-String | ForEach-Object { $_.Trim() }
            }
            else {
                Write-Host "No changes detected in ARP table." -ForegroundColor Yellow
            }
        }

        Write-Host
    }
    catch {
        Write-Error "Error: $_"
    }
}
