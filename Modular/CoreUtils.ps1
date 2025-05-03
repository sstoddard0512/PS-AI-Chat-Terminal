# CoreUtils.ps1
# Contains general utility functions, session initialization, and CSV saving logic.

#Requires -Version 5.1

# --- Helper Function: Get MIME Type ---
function Get-MimeTypeFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$FileInfo
    )
    $extension = $FileInfo.Extension.ToLowerInvariant()
    # Comprehensive MIME type list (abbreviated for brevity)
    $mimeType = switch ($extension) {
        '.jpg' { 'image/jpeg' }; '.jpeg' { 'image/jpeg' }; '.png' { 'image/png' }; '.webp' { 'image/webp' }; '.gif' { 'image/gif' }; '.heic' { 'image/heic'}; '.heif' { 'image/heif'}
        '.mp4' { 'video/mp4' }; '.mov' { 'video/quicktime' }; '.avi' { 'video/x-msvideo' }
        '.mp3' { 'audio/mpeg' }; '.wav' { 'audio/wav' }
        '.txt' { 'text/plain' }; '.pdf' { 'application/pdf' }; '.csv' { 'text/csv' }
        default { Write-Warning "[Get-MimeTypeFromFile] Cannot determine MIME type for '$($FileInfo.Name)'. Using 'application/octet-stream'."; 'application/octet-stream' }
    }
    return $mimeType
}

# --- Helper function to sanitize text for filenames ---
function Sanitize-Filename {
    [CmdletBinding()]
    param(
        [string]$InputString,
        [int]$MaxLength = 100
    )
    if ([string]::IsNullOrWhiteSpace($InputString)) { return "gemini_response_$(Get-Random)" }
    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars() -join ''; $charsToReplace = $invalidChars + ",'"; $regexInvalid = "[{0}]" -f ([RegEx]::Escape($charsToReplace))
    $sanitized = $InputString -replace $regexInvalid, '_' -replace '\s+', '_' -replace '_+', '_'
    if ($sanitized.Length -gt $MaxLength) { $sanitized = $sanitized.Substring(0, $MaxLength) }
    $sanitized = $sanitized.Trim('_')
    if ([string]::IsNullOrWhiteSpace($sanitized)) { $sanitized = "gemini_response_$(Get-Random)" }; return $sanitized
}

# --- Helper: Save Conversation to CSV ---
function Save-ChatToCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][array]$ConversationHistory,
        [Parameter(Mandatory=$true)][string]$CsvOutputFile
    )
    Write-Host "`nExporting conversation history to CSV: $CsvOutputFile" -ForegroundColor Cyan
    try {
        $csvData = [System.Collections.ArrayList]::new(); $turnNumber = 0
        for ($i = 0; $i -lt $ConversationHistory.Count; $i++) {
            $turn = $ConversationHistory[$i]; $role = $turn.role
            $text = ($turn.parts | Where-Object { $_.text } | Select-Object -ExpandProperty text) -join "`n"
            if ($role -eq 'user') { $turnNumber++ }
            [void]$csvData.Add([PSCustomObject]@{ Turn = $turnNumber; Role = $role.ToUpper(); Text = $text })
        }
        $csvData | Export-Csv -Path $CsvOutputFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "CSV export successful." -ForegroundColor Green
    } catch { Write-Error "Failed to export conversation history to CSV '$CsvOutputFile': $($_.Exception.Message)" }
}

# --- Helper: Session Initialization ---
function Initialize-GeminiChatSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$BoundParameters,
        [Parameter(Mandatory=$true)]$Invocation
    )

    Write-Verbose "[Initialize-GeminiChatSession] Initializing session..."

    # Parameters from Start-GeminiChat are directly accessible in this scope,
    # including their default values if not explicitly provided by the user.

    # Parameter Validation
    if ($MediaFolder -and [string]::IsNullOrWhiteSpace($StartPrompt)) { throw "-StartPrompt is required when -MediaFolder is specified." }
    $anyUpdateSwitch = $UpdateTitle -or $UpdateAuthor -or $UpdateSubject -or $UpdateTags -or $UpdateRating -or $UpdateLocation -or $UpdateDescription
    if ($anyUpdateSwitch -and -not $ModifyFiles) { Write-Warning "Metadata update switches (-Update*) ignored without -ModifyFiles." }
    if ($ModifyFiles -and -not $MediaFolder) { Write-Warning "-ModifyFiles requires -MediaFolder. Disabling modifications."; $ModifyFiles = $false }
    if ($UpdateAuthor -and [string]::IsNullOrWhiteSpace($AuthorName)) { throw "-AuthorName is required when -UpdateAuthor is specified." }
    if ($UpdateLocation -and -not $ModifyFiles) { Write-Warning "-UpdateLocation specified without -ModifyFiles. Location will be read/prompted but not written." }
    if ($UpdateDescription -and -not $ModifyFiles) { Write-Warning "-UpdateDescription ignored without -ModifyFiles." }
    if ($Confirm -and -not $ModifyFiles) { Write-Warning "-Confirm ignored without -ModifyFiles." }

    # File/Directory Path Validation and Creation
    $pathsToValidate = @{ CsvOutputFile = $CsvOutputFile; ResultsCsvFile = $ResultsCsvFile; OutputFile = $OutputFile }
    foreach ($item in $pathsToValidate.GetEnumerator()) {
        $paramName = $item.Name; $filePath = $item.Value
        if ($BoundParameters.ContainsKey($paramName) -and -not ([string]::IsNullOrWhiteSpace($filePath))) {
            try {
                $dir = Split-Path -Path $filePath -Parent -EA Stop
                if (-not (Test-Path -Path $dir -PathType Container)) { Write-Warning "Creating directory for -$paramName`: $dir"; New-Item -Path $dir -ItemType Directory -Force -EA Stop | Out-Null }
                "" | Out-File -FilePath $filePath -Append -Encoding UTF8 -ErrorAction Stop
                Write-Verbose "-$paramName path appears valid: $filePath"
            } catch { Write-Error "Invalid -$paramName path or cannot create/write directory: '$filePath'. Error: $($_.Exception.Message)"; return $null }
        }
    }
    if ($BoundParameters.ContainsKey('VertexDefaultOutputFolder') -and -not ([string]::IsNullOrWhiteSpace($VertexDefaultOutputFolder))) {
         try { if (-not (Test-Path -Path $VertexDefaultOutputFolder -PathType Container)) { Write-Warning "Creating -VertexDefaultOutputFolder: $VertexDefaultOutputFolder"; New-Item -Path $VertexDefaultOutputFolder -ItemType Directory -Force -EA Stop | Out-Null }; Write-Verbose "-VertexDefaultOutputFolder path appears valid." }
         catch { Write-Warning "Could not create -VertexDefaultOutputFolder '$VertexDefaultOutputFolder': $($_.Exception.Message). Will attempt creation later if needed."; }
    }

    # Check for ExifTool
    $resolvedExifToolPath = $null
    if ($ModifyFiles -or $UpdateLocation) {
        if ($ExifToolPath) {
            if ((Test-Path -LiteralPath $ExifToolPath -PathType Leaf) -and ($ExifToolPath -like '*exiftool.exe')) { $resolvedExifToolPath = $ExifToolPath }
            elseif (Test-Path -LiteralPath $ExifToolPath -PathType Container) { $potentialPath = Join-Path -Path $ExifToolPath -ChildPath 'exiftool.exe'; if (Test-Path -LiteralPath $potentialPath -PathType Leaf) { $resolvedExifToolPath = $potentialPath } else { Write-Warning "-ExifToolPath folder does not contain 'exiftool.exe'. Searching PATH." } }
            else { Write-Warning "-ExifToolPath '$ExifToolPath' not found. Searching PATH." }
        }
        if (-not $resolvedExifToolPath) { $exifToolCmd = Get-Command exiftool.exe -EA SilentlyContinue; if ($exifToolCmd) { $resolvedExifToolPath = $exifToolCmd.Path } }
        if (-not $resolvedExifToolPath) { Write-Error "ExifTool not found. Required for -ModifyFiles or -UpdateLocation."; $ModifyFiles = $false; $UpdateLocation = $false; Write-Warning "Disabling -ModifyFiles and -UpdateLocation." }
        else { Write-Verbose "Using ExifTool at: $resolvedExifToolPath" }
    }

    # Final API Key Check
    if ([string]::IsNullOrWhiteSpace($ApiKey)) { Write-Error "API Key is missing."; return $null }

    # Create Session Configuration Hashtable
    # Use the parameter variables directly - they hold the correct value (passed or default)
    $sessionConfig = @{
        Model=$Model; TimeoutSec=$TimeoutSec; MaxRetries=$MaxRetries; InitialRetryDelaySec=$InitialRetryDelaySec; FileDelaySec=$FileDelaySec;
        MediaFolder=$MediaFolder; RecurseFiles=$RecurseFiles; ModifyFiles=$ModifyFiles; ConfirmModifications=$Confirm;
        UpdateTitle=$UpdateTitle; UpdateAuthor=$UpdateAuthor; AuthorName=$AuthorName; UpdateSubject=$UpdateSubject; UpdateTags=$UpdateTags;
        UpdateRating=$UpdateRating; UpdateLocation=$UpdateLocation; UpdateDescription=$UpdateDescription; ExifToolPath=$resolvedExifToolPath;
        OutputFile=$OutputFile; CsvOutputFile=$CsvOutputFile; ResultsCsvFile=$ResultsCsvFile;
        # Note: Switches like $RecurseFiles are [switch] type, accessing $RecurseFiles.IsPresent might be safer if needed elsewhere, but direct use here is okay for hashtable.
        VertexProjectId=$VertexProjectId; VertexLocationId=$VertexLocationId; VertexDefaultOutputFolder=$VertexDefaultOutputFolder; VertexImageModel=$VertexImageModel;
        GenerationConfig=$GenerationConfig; Verbose=($VerbosePreference -eq 'Continue')
    }

    # Initial Messages
    Write-Host "`nWelcome to the Unified Gemini Chat Script (v4.0.0 - Modular)!" -ForegroundColor Cyan
    Write-Host "Interactive chat, file processing, metadata modification, Vertex AI generation." -ForegroundColor Gray
    # Combine Gemini and Vertex model display if Vertex is configured
    $modelDisplay = "Gemini Model: $($sessionConfig.Model)"
    if ($sessionConfig.VertexProjectId -and $sessionConfig.VertexLocationId -and $sessionConfig.VertexDefaultOutputFolder) { $modelDisplay += " | Vertex Image Model: $($sessionConfig.VertexImageModel)" }
    Write-Host "Session started (Mods: $($sessionConfig.ModifyFiles)). $modelDisplay" -ForegroundColor Cyan

    $activeFlagsList = [System.Collections.Generic.List[string]]::new()
    foreach ($key in ($BoundParameters.Keys | Sort-Object)) {
        $param = $Invocation.MyCommand.Parameters[$key]
        if ($param.ParameterType -eq [switch]) { if ($BoundParameters[$key]) { $activeFlagsList.Add("-$key") } }
        elseif ($key -notin @('ApiKey', 'StartPrompt', 'GenerationConfig') -and $BoundParameters[$key]) { $activeFlagsList.Add("-$key") }
    }
    if ($activeFlagsList.Count -gt 0) { Write-Host "Active Flags: $($activeFlagsList -join ', ')" -ForegroundColor Cyan } else { Write-Host "Active Flags: None" -ForegroundColor Cyan }
    if ($sessionConfig.ModifyFiles) { Write-Host "Modifications Enabled. $($sessionConfig.ConfirmModifications ? 'Confirmation required.' : 'Automatic changes.')" -ForegroundColor Yellow }
    if ($sessionConfig.UpdateLocation) { Write-Host "Location Processing Enabled." -ForegroundColor Yellow }
    if ($sessionConfig.MediaFolder -and $sessionConfig.FileDelaySec -gt 0) { Write-Host "File Delay: $($sessionConfig.FileDelaySec)s." -ForegroundColor Cyan }
    if ($sessionConfig.VertexProjectId -and $sessionConfig.VertexLocationId -and $sessionConfig.VertexDefaultOutputFolder) { Write-Host "Vertex AI Configured." -ForegroundColor Cyan } else { Write-Warning "Vertex AI parameters not fully specified. Commands will prompt if used." }
    if ($sessionConfig.ResultsCsvFile) { Write-Host "Saving parsed results to: $($sessionConfig.ResultsCsvFile)" -ForegroundColor Cyan }
    if ($sessionConfig.CsvOutputFile) { Write-Host "Saving history to: $($sessionConfig.CsvOutputFile)" -ForegroundColor Cyan }
    if ($sessionConfig.OutputFile) { Write-Host "Appending chat log to: $($sessionConfig.OutputFile)" -ForegroundColor Cyan }
    Write-Host "------------------------------------------" -ForegroundColor Cyan

    return $sessionConfig
}

Write-Verbose "CoreUtils.ps1 loaded."