#Requires -Version 5.1
# Requires ExifTool (https://exiftool.org/) for -ModifyFiles or -UpdateLocation features.
# Ensure gcloud CLI is installed and authenticated for Vertex AI features (/generate, /generate_from, /imagemodel).

# --- Script Header ---
<#
.SYNOPSIS
Starts a modular, interactive chat session with Google Gemini, supporting initial media file processing, metadata modifications, location processing, interactive media uploads, and Vertex AI image generation.
.DESCRIPTION
Refactored version of Start-GeminiChat (v4.0.0).
Initiates a conversation with Gemini. Processes initial media files (-MediaFolder, -StartPrompt) one-by-one.
Supports metadata modification (-ModifyFiles, -Update*, -Confirm) via ExifTool.
Supports location processing (-UpdateLocation) via ExifTool.
Supports interactive media upload (folder or file) via /media command.
Includes rate limit delay (-FileDelaySec).
Handles large file uploads (>20MB) via Google AI File API.
Provides interactive commands: /history, /clear, /retry, /config, /save, /media, /generate, /generate_from, /model, /imagemodel.
Includes CSV export functionality (-CsvOutputFile, /save) and parsed results CSV export (-ResultsCsvFile).
Allows specifying and changing Gemini and Vertex AI models interactively.
Modular design with helper functions for improved readability and maintenance.

.NOTES
Version: 4.0.0 (Refactored from v3.5.11)
Author: Refactored by AI Assistant (based on original script v3.5.11)
Date: 2024-07-27

Refactoring Changes:
- Modularized main function logic into helpers: Initialize-GeminiChatSession, Process-InitialMediaFiles, Handle-ChatCommand, Update-FileWithGeminiResults, Get-GpsFromExif, Invoke-ExifToolUpdate, Get-ChatInput, Process-ApiResult, Ensure-VertexAiConfig.
- Moved all helper functions to the top level.
- Improved readability, comments, and use of splatting.
- Centralized ExifTool interactions and path checking.
- Added dynamic prompting for missing Vertex AI config when needed.
- Maintained original functionality and parameters.
#>

# --- Core Helper Functions ---

function Get-MimeTypeFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$FileInfo
    )
    $extension = $FileInfo.Extension.ToLowerInvariant()
    # Comprehensive MIME type list (abbreviated for example)
    $mimeType = switch ($extension) {
        '.jpg' { 'image/jpeg' }; '.jpeg' { 'image/jpeg' }; '.png' { 'image/png' }; '.webp' { 'image/webp' }; '.gif' { 'image/gif' }; '.heic' { 'image/heic'}; '.heif' { 'image/heif'}; '.bmp' { 'image/bmp'}; '.tif' { 'image/tiff'}; '.tiff' { 'image/tiff'}
        '.mp4' { 'video/mp4' }; '.mov' { 'video/quicktime' }; '.avi' { 'video/x-msvideo' }; '.webm' { 'video/webm' }; '.mkv' { 'video/x-matroska'} # etc.
        '.mp3' { 'audio/mpeg' }; '.wav' { 'audio/wav' }; '.flac' { 'audio/flac' } # etc.
        '.txt' { 'text/plain' }; '.pdf' { 'application/pdf' }; '.csv' { 'text/csv' } # etc.
        default { Write-Warning "[Get-MimeTypeFromFile] Cannot determine MIME type for '$($FileInfo.Name)'. Using 'application/octet-stream'."; 'application/octet-stream' }
    }
    return $mimeType
}

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

function Upload-GeminiFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$FileInfo,
        [int]$TimeoutSec = 180
    )
    Write-Verbose "[Upload-GeminiFile] Uploading '$($FileInfo.Name)' ($(($FileInfo.Length / 1MB).ToString('F2')) MB) via File API..."
    $uploadUrl = "https://generativelanguage.googleapis.com/v1beta/files?key=$ApiKey"
    $mimeType = Get-MimeTypeFromFile -FileInfo $FileInfo
    if ([string]::IsNullOrWhiteSpace($mimeType) -or $mimeType -eq 'application/octet-stream') {
        Write-Error "[Upload-GeminiFile] Cannot determine valid MIME type for '$($FileInfo.Name)'. Upload aborted."
        return $null
    }
    $result = @{ Success = $false; FileUri = $null; ErrorRecord = $null }
    $userAgent = "PowerShell-GeminiApi-Client/FileUploader-4.0.0"
    $totalSize = $FileInfo.Length; $startTime = Get-Date; $progressId = Get-Random

    $progressScriptBlock = { param($FileName, $TotalSize, $ProgressId, $StartTime); while ($true) { $elapsed = (Get-Date) - $StartTime; $status = "Uploading '$FileName' ({0:F2} MB) - Elapsed: {1:hh\:mm\:ss}" -f ($TotalSize / 1MB), $elapsed; Write-Progress -Activity "Uploading via File API" -Status $status -Id $ProgressId -SecondsRemaining -1; Start-Sleep -Milliseconds 500 } }
    $progressJob = $null
    try {
        if (Get-Command Start-ThreadJob -EA SilentlyContinue) { $progressJob = Start-ThreadJob -ScriptBlock $progressScriptBlock -ArgumentList $FileInfo.Name, $totalSize, $progressId, $startTime }
        else { $progressJob = Start-Job -ScriptBlock $progressScriptBlock -ArgumentList $FileInfo.Name, $totalSize, $progressId, $startTime }
        Write-Verbose "[Upload-GeminiFile] Started progress reporting job (ID: $($progressJob.Id))."
        $headers = @{ "X-Goog-Upload-Protocol" = "raw"; "X-Goog-Upload-File-Name" = $FileInfo.Name; "Content-Type" = $mimeType; "User-Agent" = $userAgent }
        Write-Verbose "[Upload-GeminiFile] Sending upload request to $uploadUrl..."
        $response = Invoke-RestMethod -Uri $uploadUrl -Method Post -Headers $headers -InFile $FileInfo.FullName -TimeoutSec $TimeoutSec -ErrorAction Stop
        if ($response?.file?.uri) { $result.Success = $true; $result.FileUri = $response.file.uri; Write-Verbose "[Upload-GeminiFile] Upload successful. URI: $($result.FileUri)" }
        else { throw "File API response did not contain expected file URI. Response: $($response | ConvertTo-Json -Depth 3 -Compress)" }
    } catch {
        $result.ErrorRecord = $_; Write-Error "[Upload-GeminiFile] Failed to upload file '$($FileInfo.Name)': $($_.Exception.Message)"
        if ($_.Exception.Response) { try { $stream = $_.Exception.Response.GetResponseStream(); $reader = New-Object System.IO.StreamReader($stream); $errorBody = $reader.ReadToEnd(); $reader.Close(); Write-Error "[Upload-GeminiFile] Error Body: $errorBody" } catch { Write-Warning "[Upload-GeminiFile] Could not read error response body." } }
    } finally {
        if ($progressJob) { Write-Verbose "[Upload-GeminiFile] Stopping progress job..."; Stop-Job $progressJob -EA SilentlyContinue; Remove-Job $progressJob -Force -EA SilentlyContinue; Write-Progress -Activity "Uploading via File API" -Id $progressId -Completed -EA SilentlyContinue; Write-Verbose "[Upload-GeminiFile] Progress job stopped." }
    }
    return [PSCustomObject]$result
}

function Invoke-GeminiApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$ApiKey,
        [Parameter(Mandatory = $true)] [string]$Prompt,
        [array]$ConversationHistory,
        [string]$Model = 'gemini-1.5-pro-latest',
        [string]$ImageFolder,
        [string]$VideoFolder,
        [switch]$Recurse,
        [hashtable]$GenerationConfig,
        [int]$TimeoutSec = 300,
        [ValidateRange(0, 5)] [int]$MaxRetries = 3,
        [ValidateRange(1, 60)] [int]$InitialRetryDelaySec = 2,
        [string[]]$InlineFilePaths
    )
    Begin {
        Write-Verbose "[Invoke-GeminiApi] Starting function (v4.0.0)."
        $apiUrlTemplate = "https://generativelanguage.googleapis.com/v1beta/models/{0}:generateContent?key={1}"
        $apiUrl = $apiUrlTemplate -f $Model, $ApiKey
        Write-Verbose "[Invoke-GeminiApi] Using API URL: $apiUrl"
        $maxInlineDataSizeBytes = 20 * 1024 * 1024 # 20MB
    }
    Process {
        $result = [PSCustomObject]@{ Success = $false; GeneratedText = $null; ModelUsed = $Model; UpdatedConversationHistory = $null; ErrorRecord = $null; StatusCode = $null; ResponseBody = $null }
        $currentUserParts = [System.Collections.ArrayList]::new(); [void]$currentUserParts.Add(@{ text = $Prompt })

        # --- Internal Helper: Find and Add Media Part ---
        function Add-MediaPart {
            param([string]$ApiKey, [System.IO.FileInfo]$FileInfo, [long]$MaxSize, [System.Collections.ArrayList]$PartsList)
            $mimeType = Get-MimeTypeFromFile -FileInfo $FileInfo
            if ([string]::IsNullOrWhiteSpace($mimeType) -or $mimeType -eq 'application/octet-stream') {
                Write-Warning "[Invoke-GeminiApi] Could not determine valid MIME type for '$($FileInfo.Name)'. Skipping file."
                return $false # Indicate failure
            }

            if ($FileInfo.Length -lt $MaxSize) {
                Write-Verbose "[Invoke-GeminiApi] Encoding inline: '$($FileInfo.Name)' ($(($FileInfo.Length / 1MB).ToString('F2')) MB)..."
                $fileBytes = [System.IO.File]::ReadAllBytes($FileInfo.FullName); $base64Data = [System.Convert]::ToBase64String($fileBytes)
                [void]$PartsList.Add(@{ inline_data = @{ mime_type = $mimeType; data = $base64Data } })
            } else {
                Write-Verbose "[Invoke-GeminiApi] File '$($FileInfo.Name)' ($(($FileInfo.Length / 1MB).ToString('F2')) MB) >= $($MaxSize / 1MB)MB. Using File API..."
                $uploadResult = Upload-GeminiFile -ApiKey $ApiKey -FileInfo $FileInfo
                if ($uploadResult -and $uploadResult.Success) {
                    [void]$PartsList.Add(@{ file_data = @{ mime_type = $mimeType; file_uri = $uploadResult.FileUri } })
                } else {
                    throw "Failed to upload large file '$($FileInfo.Name)' via File API. Error: $($uploadResult.ErrorRecord.Exception.Message)"
                }
            }
            return $true # Indicate success
        }
        # --- End Internal Helper ---

        # --- Process Media ---
        try {
            $allMediaFiles = [System.Collections.ArrayList]::new()
            # Priority 1: InlineFilePaths
            if ($PSBoundParameters.ContainsKey('InlineFilePaths') -and $InlineFilePaths) {
                Write-Verbose "[Invoke-GeminiApi] Processing $($InlineFilePaths.Count) file(s) from -InlineFilePaths."
                foreach ($filePath in $InlineFilePaths) {
                    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) { Write-Warning "[Invoke-GeminiApi] File not found: '$filePath'. Skipping."; continue }
                    [void]$allMediaFiles.Add((Get-Item -LiteralPath $filePath -EA Stop))
                }
            }
            # Priority 2: Folder-based
            elseif ($PSBoundParameters.ContainsKey('ImageFolder') -or $PSBoundParameters.ContainsKey('VideoFolder')) {
                 Write-Verbose "[Invoke-GeminiApi] Processing media from -ImageFolder/-VideoFolder..."
                 function Get-MediaFilesInternal { param([string]$Path, [switch]$Recurse, [string[]]$Ext) try { $p = @{Path=$Path; File=$true; EA='Stop'}; if($Recurse){$p.Recurse=$true}; (Get-ChildItem @p | Where-Object {$Ext -contains $_.Extension.ToLowerInvariant()})} catch { Write-Error "Failed search: '$Path': $($_.Exception.Message)"; return $null } }
                 $imgExt = @('.jpg', '.jpeg', '.png', '.webp', '.gif', '.heic', '.heif', '.bmp', '.tif', '.tiff')
                 $vidExt = @('.mp4', '.mpeg', '.mov', '.avi', '.flv', '.mpg', '.webm', '.wmv', '.3gp', '.3gpp', '.mkv')
                 if ($PSBoundParameters.ContainsKey('ImageFolder')) { $imgFiles = Get-MediaFilesInternal -Path $ImageFolder -Recurse:$Recurse.IsPresent -Ext $imgExt; if ($imgFiles) { $imgFiles | ForEach-Object { [void]$allMediaFiles.Add($_) } } }
                 if ($PSBoundParameters.ContainsKey('VideoFolder') -and $VideoFolder -ne $ImageFolder) { $vidFiles = Get-MediaFilesInternal -Path $VideoFolder -Recurse:$Recurse.IsPresent -Ext $vidExt; if ($vidFiles) { $vidFiles | ForEach-Object { [void]$allMediaFiles.Add($_) } } }
                 Write-Verbose "[Invoke-GeminiApi] Found $($allMediaFiles.Count) media file(s) in folders."
            }
            else { Write-Verbose "[Invoke-GeminiApi] No media files provided for this call." }

            # Add valid media files to parts
            foreach ($fileInfo in $allMediaFiles) {
                 $addSuccess = Add-MediaPart -ApiKey $ApiKey -FileInfo $fileInfo -MaxSize $maxInlineDataSizeBytes -PartsList $currentUserParts
                 if (-not $addSuccess) {
                     # Handle skipping or error reporting if needed, already warned in Add-MediaPart
                 }
            }
        } catch {
            Write-Error "[Invoke-GeminiApi] Failed processing media: $($_.Exception.Message)";
            $result.ErrorRecord = $_; $result.Success = $false; return $result
        }
        # --- End Process Media ---

        # Build conversation history payload
        $currentHistoryPayload = [System.Collections.ArrayList]::new()
        if ($ConversationHistory) { $ConversationHistory | ForEach-Object { [void]$currentHistoryPayload.Add($_) }; Write-Verbose "[Invoke-GeminiApi] Using history ($($ConversationHistory.Count) turns)." }
        else { Write-Verbose "[Invoke-GeminiApi] Starting new conversation." }

        $currentUserTurn = @{ role = 'user'; parts = $currentUserParts.ToArray() }; # Convert ArrayList to Array for JSON
        [void]$currentHistoryPayload.Add($currentUserTurn)

        $requestPayload = @{ contents = $currentHistoryPayload.ToArray() } # Convert ArrayList to Array for JSON
        if ($GenerationConfig) { $requestPayload.Add('generationConfig', $GenerationConfig); Write-Verbose "[Invoke-GeminiApi] Added GenerationConfig." }

        # API Call with Retry Logic
        $currentRetry = 0; $response = $null; $userAgent = "PowerShell-GeminiApi-Client/Unified-4.0.0"
        while ($currentRetry -le $MaxRetries) {
            try {
                $requestBodyJson = $requestPayload | ConvertTo-Json -Depth 15
                Write-Verbose "[Invoke-GeminiApi] Sending request (Attempt $($currentRetry + 1)). JSON Preview: $($requestBodyJson.Substring(0, [System.Math]::Min($requestBodyJson.Length, 500)))..."
                $headers = @{ "Content-Type" = "application/json"; "User-Agent" = $userAgent }
                $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $requestBodyJson -ContentType "application/json" -TimeoutSec $TimeoutSec -ErrorAction Stop
                Write-Verbose "[Invoke-GeminiApi] Request successful."
                break # Exit loop on success
            }
            catch [System.Net.WebException] {
                $webEx = $_; $statusCode = if ($webEx.Exception.Response) { [int]$webEx.Exception.Response.StatusCode } else { $null }
                $result.ErrorRecord = $webEx; $result.StatusCode = $statusCode
                try { if ($webEx.Exception.Response) { $stream = $webEx.Exception.Response.GetResponseStream(); $reader = New-Object System.IO.StreamReader($stream); $result.ResponseBody = $reader.ReadToEnd(); $reader.Close(); if ($statusCode -eq 400) { Write-Error "[Invoke-GeminiApi] 400 Bad Request Body: $($result.ResponseBody)" } Write-Verbose "[Invoke-GeminiApi] Error Body: $($result.ResponseBody)" } } catch { Write-Warning "Could not read error response body." }
                $errorMsg = "[Invoke-GeminiApi] Web exception (Status: $statusCode)."
                if ($statusCode -eq 400) { $errorMsg += " Check API key, request format (prompt, config, file data), model/region, content policy." }
                if ($statusCode -eq 429 -and $currentRetry -lt $MaxRetries) {
                    $currentRetry++; $delay = ($InitialRetryDelaySec * ([Math]::Pow(2, $currentRetry - 1))) + (Get-Random -Minimum 0 -Maximum 1000) / 1000.0
                    Write-Warning "[Invoke-GeminiApi] HTTP 429. Retrying attempt $currentRetry/$($MaxRetries + 1) in $($delay.ToString('F2'))s..."
                    Start-Sleep -Seconds $delay; continue
                } else { Write-Error $errorMsg; break }
            }
            catch { $errMsg = "[Invoke-GeminiApi] Unexpected error: $($_.Exception.Message)"; Write-Error $errMsg; $result.ErrorRecord = $_; $result.ResponseBody = $errMsg; break }
        } # End while

        # Process the final response
        if ($response) {
            if ($response.candidates[0]?.content?.parts[0]?.text) {
                $result.GeneratedText = $response.candidates[0].content.parts[0].text
                $result.Success = $true; $result.StatusCode = 200
                Write-Verbose "[Invoke-GeminiApi] Parsed response successfully."
                $modelResponseTurn = $response.candidates[0].content
                [void]$currentHistoryPayload.Add($modelResponseTurn)
                $result.UpdatedConversationHistory = $currentHistoryPayload.ToArray() # Return as Array
            } elseif ($response.promptFeedback?.blockReason) {
                $blockReason = $response.promptFeedback.blockReason; $ratings = $response.promptFeedback.safetyRatings | ConvertTo-Json -Depth 3 -Compress
                $errMsg = "[Invoke-GeminiApi] Request blocked. Reason: $blockReason. Ratings: $ratings"; Write-Error $errMsg
                $result.ResponseBody = $response | ConvertTo-Json -Depth 10
                $result.ErrorRecord = New-Object System.Management.Automation.ErrorRecord -ArgumentList @([System.Exception]::new($errMsg), "SafetyBlock", [System.Management.Automation.ErrorCategory]::PermissionDenied, $response); $result.StatusCode = 200
            } else {
                Write-Warning "[Invoke-GeminiApi] API response received but structure unexpected (no candidate text or block reason)."
                $result.ResponseBody = $response | ConvertTo-Json -Depth 10; $result.StatusCode = 200
                $result.ErrorRecord = New-Object System.Management.Automation.ErrorRecord -ArgumentList @([System.Exception]::new("Unexpected API response structure."), "UnexpectedApiResponseStructure", [System.Management.Automation.ErrorCategory]::InvalidData, $response)
            }
        } elseif (-not $result.ErrorRecord) {
            Write-Error "[Invoke-GeminiApi] API call failed after retries, no specific error captured."
            $result.ErrorRecord = New-Object System.Management.Automation.ErrorRecord -ArgumentList @([System.Exception]::new("API call failed after retries."), "ApiRetryFailure", [System.Management.Automation.ErrorCategory]::OperationTimeout, $null)
        }

        Write-Verbose "[Invoke-GeminiApi] Function finished."
        return $result
    }
    End { }
}

function Get-StartMediaFiles {
    [CmdletBinding()]
    param(
        [string]$FolderPath,
        [switch]$Recurse,
        [string[]]$SupportedExtensions,
        [string]$MediaType,
        [string]$ExcludePath # Add parameter to exclude log file path
    )
    Write-Verbose "[Get-StartMediaFiles] Searching for $MediaType files in: $FolderPath $($Recurse.IsPresent ? '(Recursive)' : '')"
    $discoveredFiles = [System.Collections.ArrayList]::new()
    try {
        $gciParams = @{ Path = $FolderPath; File = $true; ErrorAction = 'Stop' }
        if ($Recurse.IsPresent) { $gciParams.Recurse = $true }
        $allFiles = Get-ChildItem @gciParams | Where-Object { $SupportedExtensions -contains $_.Extension.ToLowerInvariant() }

        # Filter out the excluded path if provided
        foreach ($file in $allFiles) {
            if ($ExcludePath -and ($file.FullName -eq (Resolve-Path -LiteralPath $ExcludePath -ErrorAction SilentlyContinue))) {
                 Write-Verbose "  [Get-StartMediaFiles] Skipping excluded file: $($file.Name)"
            } else {
                [void]$discoveredFiles.Add($file)
            }
        }
        Write-Verbose "[Get-StartMediaFiles] Found $($discoveredFiles.Count) $MediaType file(s) after exclusion."
        return $discoveredFiles.ToArray() # Return as array
    } catch {
        Write-Error "[Get-StartMediaFiles] Failed to access/search folder '$FolderPath': $($_.Exception.Message)"; return @() # Return empty array on error
    }
}

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

function Parse-GeminiResponse {
    [CmdletBinding()]
    param(
        [string]$GeminiText
    )
    Write-Verbose "[Parse-GeminiResponse] Parsing response..."
    $parsedData = @{ Name = $null; Description = $null; Rating = $null; Location = $null; Tags = [System.Collections.ArrayList]::new() }
    if (-not [string]::IsNullOrWhiteSpace($GeminiText)) {
        $lines = $GeminiText -split '\r?\n'
        foreach ($line in $lines) {
            $trimmedLine = $line.Trim()
            if ($trimmedLine -match '^\s*(?:\*\*?)?(?:\d+\.\s*)?(?i)Name:\s*(.+?)\s*$') { $parsedData.Name = $Matches[1].Trim('*_ ') }
            elseif ($trimmedLine -match '^\s*(?:\*\*?\s*\d+\.\s*)?(?i)Rating:\s*([0-5])') { $parsedData.Rating = [int]$Matches[1] }
            elseif ($trimmedLine -match '^\s*(?:\*\*?\s*\d+\.\s*)?(?i)(?:Tags:|Keywords:)\s*(.*)$') { $tagString = $Matches[1].Trim('*_ '); $tagsFromLine = $tagString -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }; if ($tagsFromLine) { $tagsFromLine | ForEach-Object { [void]$parsedData.Tags.Add($_) } } }
            elseif ($trimmedLine -match '^\s*(?:\*\*?)?(?:\d+\.\s*)?(?i)Location:\s*(.+?)\s*$') { $parsedData.Location = $Matches[1].Trim('*_ ') }
            elseif ($trimmedLine -match '^\s*(?:\*\*?\s*\d+\.\s*)?(?i)Description:\s*(.+)$') { $parsedData.Description = $Matches[1].Trim('*_ ') }
        }
        Write-Verbose "[Parse-GeminiResponse] Parsed Name: $($parsedData.Name), Rating: $($parsedData.Rating), Tags: $($parsedData.Tags.Count), Location: $($parsedData.Location), Desc: $(if ($parsedData.Description) {$($parsedData.Description.Length)} else {0}) chars."
    } else { Write-Warning "[Parse-GeminiResponse] Response text is empty." }
    # Convert Tags ArrayList to Array before returning PSCustomObject
    $parsedData.Tags = $parsedData.Tags.ToArray()
    return [PSCustomObject]$parsedData
}

function Save-ParsedResultsToCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][System.IO.FileInfo]$OriginalFileInfo,
        [Parameter(Mandatory=$true)]$ParsedData, # Expects the PSCustomObject from Parse-GeminiResponse
        [Parameter(Mandatory=$true)][string]$ResultsCsvFilePath
    )
    Write-Verbose "[Save-ParsedResultsToCsv] Saving parsed results for '$($OriginalFileInfo.Name)' to '$ResultsCsvFilePath'"
    try {
        $outputObject = [PSCustomObject]@{
            OriginalFilename = $OriginalFileInfo.Name
            ParsedName       = $ParsedData.Name
            ParsedDescription= $ParsedData.Description
            ParsedRating     = $ParsedData.Rating
            ParsedLocation   = $ParsedData.Location
            ParsedTags       = $ParsedData.Tags -join '; ' # Join tags array into a single string
        }
        $writeHeader = (-not (Test-Path -LiteralPath $ResultsCsvFilePath)) -or ((Get-Item -LiteralPath $ResultsCsvFilePath).Length -eq 0)
        $outputObject | Export-Csv -Path $ResultsCsvFilePath -NoTypeInformation -Encoding UTF8 -Append:(-not $writeHeader) -ErrorAction Stop
        Write-Verbose "[Save-ParsedResultsToCsv] Successfully saved results for '$($OriginalFileInfo.Name)'."
    } catch { Write-Warning "[Save-ParsedResultsToCsv] Failed to save parsed results for '$($OriginalFileInfo.Name)' to '$ResultsCsvFilePath': $($_.Exception.Message)" }
}

# --- Vertex AI Image Generation Function (Start-VertexImageGeneration - unchanged from original script v3.5.11) ---
function Start-VertexImageGeneration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Your Google Cloud Project ID.")]
        [string]$ProjectId,
        [Parameter(Mandatory = $true, HelpMessage = "The Google Cloud location ID (e.g., 'us-central1').")]
        [string]$LocationId,
        [Parameter(Mandatory = $true, HelpMessage = "Text prompt describing the image(s).")]
        [string]$Prompt,
        [Parameter(HelpMessage = "Optional text prompt describing elements to avoid.")]
        [string]$NegativePrompt,
        [Parameter(Mandatory = $true, HelpMessage = "Folder to save generated images.")]
        [string]$OutputFolder,
        [Parameter(HelpMessage = "Number of images to generate (1-8).")]
        [ValidateRange(1, 8)]
        [int]$Count = 1,
        [Parameter(HelpMessage = "The Vertex AI Imagen model ID.")]
        [string]$ModelId = 'imagegeneration@006', # Example model, check docs for latest
        [Parameter(HelpMessage = "Image dimensions (e.g., '1024x1024').")]
        [string]$Size,
        [Parameter(HelpMessage = "Base name for output files.")]
        [string]$OutputFileNameBase,
        [Parameter(HelpMessage = "Desired aspect ratio (e.g., '1:1', '16:9').")]
        [string]$AspectRatio,
        [Parameter(HelpMessage = "Seed for deterministic generation.")]
        [int]$Seed
    )

    # --- Check for gcloud ---
    $gcloudPath = Get-Command gcloud -ErrorAction SilentlyContinue
    if (-not $gcloudPath) { Write-Error "Google Cloud SDK ('gcloud') not found in PATH. Please install and authenticate it."; return }
    Write-Verbose "Using gcloud found at: $($gcloudPath.Path)"

    # --- Get Access Token ---
    Write-Verbose "Attempting to get access token via 'gcloud auth print-access-token'..."
    try {
        $gcloudOutput = gcloud auth print-access-token --quiet 2>&1
        if ($LASTEXITCODE -ne 0) { throw "gcloud command failed (ExitCode: $LASTEXITCODE). Output: $($gcloudOutput -join '; ')" }
        $accessToken = $gcloudOutput
        if ([string]::IsNullOrWhiteSpace($accessToken)) { throw "Received empty access token." }
        Write-Verbose "Successfully obtained access token."
    } catch { Write-Error "Failed to get access token using 'gcloud auth print-access-token'. Ensure you are authenticated. Error: $($_.Exception.Message)"; return }

    # --- Prepare Output Folder ---
    try { if (-not (Test-Path -LiteralPath $OutputFolder -PathType Container)) { Write-Warning "Output folder '$OutputFolder' does not exist. Creating..."; New-Item -Path $OutputFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null; Write-Verbose "Created output folder: $OutputFolder" } }
    catch { Write-Error "Failed to create output folder '$OutputFolder'. Error: $($_.Exception.Message)"; return }

    # --- Construct API Request ---
    $apiUrl = "https://${LocationId}-aiplatform.googleapis.com/v1/projects/${ProjectId}/locations/${LocationId}/publishers/google/models/${ModelId}:predict"
    Write-Verbose "Using Vertex AI endpoint: $apiUrl"
    $requestBody = @{ instances = @(@{ prompt = $Prompt }); parameters = @{ sampleCount = $Count } }
    if ($NegativePrompt) { $requestBody.parameters.negativePrompt = $NegativePrompt }
    if ($Size) { $dims = $Size -split 'x'; if ($dims.Length -eq 2 -and $dims[0] -as [int] -and $dims[1] -as [int]) { $requestBody.parameters.add('width', [int]$dims[0]); $requestBody.parameters.add('height', [int]$dims[1]); Write-Verbose "Added size: $($dims[0])x$($dims[1])"} else { Write-Warning "Invalid -Size format '$Size'. Ignoring." } }
    if ($AspectRatio) { $requestBody.parameters.aspectRatio = $AspectRatio; Write-Verbose "Added aspectRatio: $AspectRatio" }
    if ($PSBoundParameters.ContainsKey('Seed')) { $requestBody.parameters.seed = $Seed; Write-Verbose "Added seed: $Seed" }
    $headers = @{ "Authorization" = "Bearer $accessToken"; "Content-Type" = "application/json; charset=utf-8" }
    $requestBodyJson = $requestBody | ConvertTo-Json -Depth 5; Write-Verbose "Request Body JSON: $requestBodyJson"

    # --- Call API ---
    Write-Host "Sending request to Vertex AI Imagen API (Model: $ModelId)..." -ForegroundColor DarkGray; $response = $null
    try { $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $requestBodyJson -ContentType "application/json; charset=utf-8" -TimeoutSec 300 -ErrorAction Stop }
    catch { Write-Error "Vertex AI API call failed: $($_.Exception.Message)"; if ($_.Exception.Response) { try { $stream = $_.Exception.Response.GetResponseStream(); $reader = New-Object System.IO.StreamReader($stream); $errorBody = $reader.ReadToEnd(); $reader.Close(); if ($errorBody) { Write-Error "Error Response Body: $errorBody" } } catch { Write-Warning "Could not read error response body." } }; return }

    # --- Process Response and Save Images ---
    if ($response?.predictions -is [array] -and $response.predictions.Count -gt 0) {
        Write-Host "API call successful. Processing $($response.predictions.Count) image(s)..." -ForegroundColor Green
        $baseFileName = if ($OutputFileNameBase) { Sanitize-Filename -InputString $OutputFileNameBase } else { Sanitize-Filename -InputString $Prompt -MaxLength 50 }
        $imageIndex = 0
        foreach ($prediction in $response.predictions) {
            $imageIndex++
            if ($prediction.bytesBase64Encoded) {
                try {
                    $imageBytes = [System.Convert]::FromBase64String($prediction.bytesBase64Encoded)
                    $suffix = if ($Count -gt 1 -or $response.predictions.Count -gt 1) { "_$($imageIndex)" } else { "" }
                    $outputFilePath = Join-Path -Path $OutputFolder -ChildPath "$($baseFileName)${suffix}.png"
                    $collisionIndex = 1; $originalOutputFilePath = $outputFilePath
                    while (Test-Path -LiteralPath $outputFilePath) { $outputFilePath = Join-Path -Path $OutputFolder -ChildPath "$($baseFileName)${suffix}_$($collisionIndex).png"; $collisionIndex++ }
                    if ($outputFilePath -ne $originalOutputFilePath) { Write-Warning "Output file '$originalOutputFilePath' existed. Saving as '$outputFilePath'." }
                    [System.IO.File]::WriteAllBytes($outputFilePath, $imageBytes); Write-Host "Saved image: $outputFilePath" -ForegroundColor DarkGreen
                    try { Invoke-Item -Path $outputFilePath -ErrorAction Stop } catch { Write-Warning "Could not automatically open image '$outputFilePath': $($_.Exception.Message)" }
                } catch { Write-Warning "Failed to decode or save image $imageIndex`: $($_.Exception.Message)" }
            } else { Write-Warning "Prediction $imageIndex did not contain expected 'bytesBase64Encoded' data." }
        }
    } else { Write-Warning "API response received, but no predictions found or structure unexpected."; Write-Verbose "Full Response: $($response | ConvertTo-Json -Depth 5)" }
}


# --- MODULAR HELPER: Initialization ---
function Initialize-GeminiChatSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$BoundParameters,
        [Parameter(Mandatory=$true)]$Invocation
    )

    Write-Verbose "[Initialize-GeminiChatSession] Initializing session..."

    # Extract parameters (makes access easier)
    $ApiKey = $BoundParameters['ApiKey']
    $Model = $BoundParameters['Model']
    $GenerationConfig = $BoundParameters['GenerationConfig']
    $TimeoutSec = $BoundParameters['TimeoutSec']
    $MaxRetries = $BoundParameters['MaxRetries']
    $InitialRetryDelaySec = $BoundParameters['InitialRetryDelaySec']
    $FileDelaySec = $BoundParameters['FileDelaySec']
    $StartPrompt = $BoundParameters['StartPrompt']
    $MediaFolder = $BoundParameters['MediaFolder']
    $RecurseFiles = $BoundParameters['RecurseFiles']
    $ModifyFiles = $BoundParameters['ModifyFiles']
    $Confirm = $BoundParameters['Confirm']
    $UpdateTitle = $BoundParameters['UpdateTitle']
    $UpdateAuthor = $BoundParameters['UpdateAuthor']
    $AuthorName = $BoundParameters['AuthorName']
    $UpdateSubject = $BoundParameters['UpdateSubject']
    $UpdateTags = $BoundParameters['UpdateTags']
    $UpdateRating = $BoundParameters['UpdateRating']
    $UpdateLocation = $BoundParameters['UpdateLocation']
    $UpdateDescription = $BoundParameters['UpdateDescription']
    $ExifToolPath = $BoundParameters['ExifToolPath']
    $OutputFile = $BoundParameters['OutputFile']
    $VertexProjectId = $BoundParameters['VertexProjectId']
    $VertexLocationId = $BoundParameters['VertexLocationId']
    $VertexDefaultOutputFolder = $BoundParameters['VertexDefaultOutputFolder']
    $VertexImageModel = $BoundParameters['VertexImageModel']
    $CsvOutputFile = $BoundParameters['CsvOutputFile']
    $ResultsCsvFile = $BoundParameters['ResultsCsvFile']

    # --- Verbose Preference Handling ---
    # (Handled in Start-GeminiChat main body now)

    # --- Parameter Validation ---
    if ($MediaFolder -and [string]::IsNullOrWhiteSpace($StartPrompt)) { throw "-StartPrompt is required when -MediaFolder is specified." }
    $anyUpdateSwitch = $UpdateTitle -or $UpdateAuthor -or $UpdateSubject -or $UpdateTags -or $UpdateRating -or $UpdateLocation -or $UpdateDescription
    if ($anyUpdateSwitch -and -not $ModifyFiles) { Write-Warning "Metadata update switches (-Update*) ignored without -ModifyFiles." }
    if ($ModifyFiles -and -not $MediaFolder) { Write-Warning "-ModifyFiles requires -MediaFolder. Disabling modifications."; $ModifyFiles = $false }
    if ($UpdateAuthor -and [string]::IsNullOrWhiteSpace($AuthorName)) { throw "-AuthorName is required when -UpdateAuthor is specified." }
    if ($UpdateLocation -and -not $ModifyFiles) { Write-Warning "-UpdateLocation specified without -ModifyFiles. Location will be read/prompted but not written." }
    if ($UpdateDescription -and -not $ModifyFiles) { Write-Warning "-UpdateDescription ignored without -ModifyFiles." }
    if ($Confirm -and -not $ModifyFiles) { Write-Warning "-Confirm ignored without -ModifyFiles." }
    # Vertex partial config warning is now handled in the initial messages section

    # --- File/Directory Path Validation and Creation ---
    $pathsToValidate = @{ CsvOutputFile = $CsvOutputFile; ResultsCsvFile = $ResultsCsvFile; OutputFile = $OutputFile }
    foreach ($item in $pathsToValidate.GetEnumerator()) {
        $paramName = $item.Name; $filePath = $item.Value
        if ($BoundParameters.ContainsKey($paramName) -and -not ([string]::IsNullOrWhiteSpace($filePath))) {
            try {
                $dir = Split-Path -Path $filePath -Parent -EA Stop
                if (-not (Test-Path -Path $dir -PathType Container)) { Write-Warning "Creating directory for -$paramName`: $dir"; New-Item -Path $dir -ItemType Directory -Force -EA Stop | Out-Null }
                "" | Out-File -FilePath $filePath -Append -Encoding UTF8 -ErrorAction Stop # Test write access
                Write-Verbose "-$paramName path appears valid: $filePath"
            } catch { Write-Error "Invalid -$paramName path or cannot create/write to directory: '$filePath'. Error: $($_.Exception.Message)"; return $null } # Return null on critical error
        }
    }
    # Validate VertexDefaultOutputFolder if provided
    if ($BoundParameters.ContainsKey('VertexDefaultOutputFolder') -and -not ([string]::IsNullOrWhiteSpace($VertexDefaultOutputFolder))) {
         try {
            if (-not (Test-Path -Path $VertexDefaultOutputFolder -PathType Container)) { Write-Warning "Creating directory for -VertexDefaultOutputFolder: $VertexDefaultOutputFolder"; New-Item -Path $VertexDefaultOutputFolder -ItemType Directory -Force -EA Stop | Out-Null }
            Write-Verbose "-VertexDefaultOutputFolder path appears valid: $VertexDefaultOutputFolder"
         } catch { Write-Warning "Could not create -VertexDefaultOutputFolder '$VertexDefaultOutputFolder': $($_.Exception.Message). Will attempt creation later if needed by a command."; } # Warn but don't fail init
    }


    # --- Check for ExifTool ---
    $resolvedExifToolPath = $null
    if ($ModifyFiles -or $UpdateLocation) {
        if ($ExifToolPath) {
            if ((Test-Path -LiteralPath $ExifToolPath -PathType Leaf) -and ($ExifToolPath -like '*exiftool.exe')) { $resolvedExifToolPath = $ExifToolPath }
            elseif (Test-Path -LiteralPath $ExifToolPath -PathType Container) { $potentialPath = Join-Path -Path $ExifToolPath -ChildPath 'exiftool.exe'; if (Test-Path -LiteralPath $potentialPath -PathType Leaf) { $resolvedExifToolPath = $potentialPath } else { Write-Warning "-ExifToolPath folder does not contain 'exiftool.exe'. Searching PATH." } }
            else { Write-Warning "-ExifToolPath '$ExifToolPath' not found. Searching PATH." }
        }
        if (-not $resolvedExifToolPath) { $exifToolCmd = Get-Command exiftool.exe -EA SilentlyContinue; if ($exifToolCmd) { $resolvedExifToolPath = $exifToolCmd.Path } }
        if (-not $resolvedExifToolPath) { Write-Error "ExifTool not found via -ExifToolPath or in PATH. Required for -ModifyFiles or -UpdateLocation. Download from https://exiftool.org/."; $ModifyFiles = $false; $UpdateLocation = $false; Write-Warning "Disabling -ModifyFiles and -UpdateLocation." }
        else { Write-Verbose "Using ExifTool at: $resolvedExifToolPath" }
    }

    # --- Final API Key Check ---
    # (ApiKey is already validated/prompted in Start-GeminiChat main body)
    if ([string]::IsNullOrWhiteSpace($ApiKey)) { Write-Error "API Key is missing after initial check."; return $null }

    # --- Create Session Configuration Hashtable ---
    $sessionConfig = @{
        Model                     = $Model; TimeoutSec                = $TimeoutSec; MaxRetries                = $MaxRetries
        InitialRetryDelaySec      = $InitialRetryDelaySec; FileDelaySec              = $FileDelaySec
        MediaFolder               = $MediaFolder; RecurseFiles              = $RecurseFiles; ModifyFiles               = $ModifyFiles
        ConfirmModifications      = $Confirm; UpdateTitle               = $UpdateTitle; UpdateAuthor              = $UpdateAuthor
        AuthorName                = $AuthorName; UpdateSubject             = $UpdateSubject; UpdateTags                = $UpdateTags
        UpdateRating              = $UpdateRating; UpdateLocation            = $UpdateLocation; UpdateDescription         = $UpdateDescription
        ExifToolPath              = $resolvedExifToolPath; OutputFile                = $OutputFile; CsvOutputFile             = $CsvOutputFile
        ResultsCsvFile            = $ResultsCsvFile; VertexProjectId           = $VertexProjectId; VertexLocationId          = $VertexLocationId
        VertexDefaultOutputFolder = $VertexDefaultOutputFolder; VertexImageModel          = $VertexImageModel
        GenerationConfig          = $GenerationConfig; Verbose                   = ($VerbosePreference -eq 'Continue')
    }

    # --- Initial Messages ---
    Write-Host "`nWelcome to the Unified Gemini Chat Script (v4.0.0 - Modular)!" -ForegroundColor Cyan
    Write-Host "Interactive chat, file processing, metadata modification, Vertex AI generation." -ForegroundColor Gray
    Write-Host "Session started (Mods: $($sessionConfig.ModifyFiles)). Gemini Model: $($sessionConfig.Model)" -ForegroundColor Cyan
    if ($sessionConfig.VertexProjectId -and $sessionConfig.VertexLocationId -and $sessionConfig.VertexDefaultOutputFolder) { Write-Host "Vertex Image Model: $($sessionConfig.VertexImageModel)" -ForegroundColor Cyan }

    $activeFlagsList = [System.Collections.Generic.List[string]]::new()
    foreach ($key in ($BoundParameters.Keys | Sort-Object)) {
        $param = $Invocation.MyCommand.Parameters[$key]
        if ($param.ParameterType -eq [switch]) { if ($BoundParameters[$key]) { $activeFlagsList.Add("-$key") } }
        elseif ($key -notin @('ApiKey', 'StartPrompt', 'GenerationConfig') -and $BoundParameters[$key]) { $activeFlagsList.Add("-$key") }
    }
    if ($activeFlagsList.Count -gt 0) { Write-Host "Active Flags: $($activeFlagsList -join ', ')" -ForegroundColor Cyan } else { Write-Host "Active Flags: None" -ForegroundColor Cyan }
    if ($sessionConfig.ModifyFiles) { Write-Host "Modifications Enabled (Requires ExifTool). $($sessionConfig.ConfirmModifications ? 'Confirmation required.' : 'Automatic changes.')" -ForegroundColor Yellow }
    if ($sessionConfig.UpdateLocation) { Write-Host "Location Processing Enabled (Requires ExifTool)." -ForegroundColor Yellow }
    # (Other update flags could be listed here too if desired)
    if ($sessionConfig.MediaFolder -and $sessionConfig.FileDelaySec -gt 0) { Write-Host "File Delay: $($sessionConfig.FileDelaySec)s." -ForegroundColor Cyan }

    if ($sessionConfig.VertexProjectId -and $sessionConfig.VertexLocationId -and $sessionConfig.VertexDefaultOutputFolder) { Write-Host "Vertex AI Configured (Use /generate, /generate_from, /imagemodel)." -ForegroundColor Cyan }
    else { Write-Warning "Vertex AI parameters not fully specified. Commands will prompt if used." }

    if ($sessionConfig.ResultsCsvFile) { Write-Host "Saving parsed results to: $($sessionConfig.ResultsCsvFile)" -ForegroundColor Cyan }
    if ($sessionConfig.CsvOutputFile) { Write-Host "Saving history to: $($sessionConfig.CsvOutputFile) (on exit or /save)" -ForegroundColor Cyan }
    if ($sessionConfig.OutputFile) { Write-Host "Appending chat log to: $($sessionConfig.OutputFile)" -ForegroundColor Cyan }
    Write-Host "------------------------------------------" -ForegroundColor Cyan

    return $sessionConfig
}


# --- MODULAR HELPER: GPS Reading ---
function Get-GpsFromExif {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][System.IO.FileInfo]$FileInfo,
        [Parameter(Mandatory=$true)][string]$ResolvedExifToolPath
    )
    Write-Verbose "[Get-GpsFromExif] Reading GPS for '$($FileInfo.Name)' using ExifTool..."
    $gpsCoordsString = $null
    try {
        $imageExtensionsForGPS = @('.jpg', '.jpeg', '.heic', '.heif', '.tiff', '.tif')
        if (-not ($imageExtensionsForGPS -contains $FileInfo.Extension.ToLowerInvariant())) {
            Write-Verbose "  File type '$($FileInfo.Extension)' not typically checked for GPS."; return $null
        }

        $exifToolArgs = @('-n', '-GPSLatitude', '-GPSLongitude', '-j', '-coordFormat', '%.6f', $FileInfo.FullName)
        $process = Start-Process -FilePath $ResolvedExifToolPath -ArgumentList $exifToolArgs -Wait -NoNewWindow -RedirectStandardOutput ($stdOutFile = New-TemporaryFile) -RedirectStandardError ($stdErrFile = New-TemporaryFile) -PassThru
        $exifToolOutput = Get-Content -Path $stdOutFile.FullName
        $exifError = Get-Content -Path $stdErrFile.FullName
        Remove-Item $stdOutFile.FullName, $stdErrFile.FullName -ErrorAction SilentlyContinue
        Write-Verbose "  ExifTool GPS Read StdOut: $($exifToolOutput -join "`n  ")"
        if ($process.ExitCode -ne 0 -or $exifError) { throw "ExifTool exited with code $($process.ExitCode). Stderr: $($exifError -join '; ')" }

        $exifOutputJson = $exifToolOutput -join "" # Join lines
        $exifData = $exifOutputJson | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($exifData -is [array]) { $exifData = $exifData[0] } # ExifTool -j returns array

        if ($exifData?.GPSLatitude -and $exifData?.GPSLongitude -and $exifData.GPSLatitude -ne 0 -and $exifData.GPSLongitude -ne 0) {
             $lat = $exifData.GPSLatitude.ToString("F6", [System.Globalization.CultureInfo]::InvariantCulture)
             $lon = $exifData.GPSLongitude.ToString("F6", [System.Globalization.CultureInfo]::InvariantCulture)
             $gpsCoordsString = "GPS: $lat, $lon"
             Write-Verbose "  Found GPS: $gpsCoordsString"
        } else { Write-Verbose "  No valid GPS coordinates found." }
    } catch { Write-Warning "[Get-GpsFromExif] Error reading GPS for '$($FileInfo.Name)': $($_.Exception.Message)." }
    return $gpsCoordsString
}

# --- MODULAR HELPER: ExifTool Metadata Update ---
function Invoke-ExifToolUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ResolvedExifToolPath,
        [Parameter(Mandatory=$true)][string]$CurrentFilePath,
        [Parameter(Mandatory=$true)]$ParsedData, # PSCustomObject from Parse-GeminiResponse
        [Parameter(Mandatory=$true)]$SessionConfig # Hashtable
    )
    Write-Verbose "[Invoke-ExifToolUpdate] Updating metadata for '$CurrentFilePath'..."
    $success = $false
    try {
        $exifArgs = [System.Collections.ArrayList]::new()
        $originalFileNameBase = [System.IO.Path]::GetFileNameWithoutExtension($CurrentFilePath) # Get base name of potentially renamed file
        $titleValueForMeta = if ($ParsedData.Name) { (Sanitize-Filename -InputString $ParsedData.Name) -replace '_', ' ' } else { $originalFileNameBase }

        if ($SessionConfig.UpdateTitle -and $ParsedData.Name) { [void]$exifArgs.Add("-Title=""$titleValueForMeta"""); Write-Verbose "  Adding Title arg." }
        if ($SessionConfig.UpdateAuthor -and $SessionConfig.AuthorName) { [void]$exifArgs.Add("-Artist=""$($SessionConfig.AuthorName)"""); [void]$exifArgs.Add("-Creator=""$($SessionConfig.AuthorName)"""); Write-Verbose "  Adding Author args." }
        if ($SessionConfig.UpdateRating -and $ParsedData.Rating -ne $null) { if ($ParsedData.Rating -ge 0 -and $ParsedData.Rating -le 5) { [void]$exifArgs.Add("-Rating=$($ParsedData.Rating)"); Write-Verbose "  Adding Rating arg." } else { Write-Warning "Invalid rating '$($ParsedData.Rating)', ignoring." } }
        if ($SessionConfig.UpdateTags) {
            [void]$exifArgs.Add("-Keywords="); [void]$exifArgs.Add("-Subject="); Write-Verbose "  Clearing Keywords/Subject args."
            if ($ParsedData.Tags.Count -gt 0) { foreach ($tag in $ParsedData.Tags) { [void]$exifArgs.Add("-Keywords=""$tag"""); [void]$exifArgs.Add("-Subject=""$tag""") }; Write-Verbose "  Added $($ParsedData.Tags.Count) tags." }
        }
        if ($SessionConfig.UpdateLocation -and $ParsedData.Location) {
            $locationParts = $ParsedData.Location -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            if ($locationParts.Count -gt 0) {
                if ($locationParts[0]) { [void]$exifArgs.Add("-City=""$($locationParts[0])"""); Write-Verbose "  Adding City arg." }
                if ($locationParts.Count -gt 1 -and $locationParts[1]) { [void]$exifArgs.Add("-State=""$($locationParts[1])"""); Write-Verbose "  Adding State arg." }
                if ($locationParts.Count -gt 2 -and $locationParts[2]) { [void]$exifArgs.Add("-Country=""$($locationParts[2])"""); Write-Verbose "  Adding Country arg." }
                if (-not $SessionConfig.UpdateSubject -and -not $SessionConfig.UpdateDescription) { [void]$exifArgs.Add("-Comment=""$($ParsedData.Location)"""); Write-Verbose "  Adding Location to Comment (fallback)." }
            } else { Write-Warning "Could not parse City/State/Country from Location: '$($ParsedData.Location)'" }
        }
        if ($SessionConfig.UpdateDescription -and $ParsedData.Description) { [void]$exifArgs.Add("-Description=""$($ParsedData.Description)"""); [void]$exifArgs.Add("-Comment=""$($ParsedData.Description)"""); Write-Verbose "  Adding Description (and Comment) args." }
        elseif ($SessionConfig.UpdateSubject -and $ParsedData.Name) { [void]$exifArgs.Add("-Comment=""$titleValueForMeta"""); Write-Verbose "  Adding Title to Comment (Subject) arg." }

        if ($exifArgs.Count -gt 0) {
            [void]$exifArgs.Add("-overwrite_original"); [void]$exifArgs.Add("-m"); [void]$exifArgs.Add($CurrentFilePath)
            Write-Verbose "  Executing ExifTool with $($exifArgs.Count - 3) tag arguments..."
            $exifResult = & $ResolvedExifToolPath @exifArgs 2>&1 # Capture stdout and stderr
            Write-Verbose "  ExifTool Update Output: $($exifResult -join "`n  ")"
            if ($LASTEXITCODE -eq 0 -and ($exifResult -match '1 (image|video|audio|document|file) files? updated')) {
                Write-Host "[Metadata Updated for '$(Split-Path $CurrentFilePath -Leaf)']" -ForegroundColor DarkGreen
                $success = $true
            } else { throw "ExifTool execution failed (ExitCode: $LASTEXITCODE) or did not report success. Output: $($exifResult -join '; ')" }
        } else { Write-Host "[Metadata Unchanged for '$(Split-Path $CurrentFilePath -Leaf)'] (No relevant data/flags)" -ForegroundColor DarkGray; $success = $true } # Consider no-op as success

    } catch { Write-Warning "[Invoke-ExifToolUpdate] Failed metadata update for '$CurrentFilePath': $($_.Exception.Message)"; $success = $false }
    return $success
}


# --- MODULAR HELPER: File Rename and Metadata Update Orchestration ---
function Update-FileWithGeminiResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][System.IO.FileInfo]$FileInfo,
        [Parameter(Mandatory=$true)]$ParsedData, # PSCustomObject from Parse-GeminiResponse
        [Parameter(Mandatory=$true)]$SessionConfig, # Hashtable
        [Parameter(Mandatory=$true)]$GlobalRenameErrors, # ArrayList
        [Parameter(Mandatory=$true)]$GlobalMetadataErrors # ArrayList
    )
    Write-Verbose "[Update-FileWithGeminiResults] Checking modifications for '$($FileInfo.Name)'..."
    $processedCount = 0; $skippedCount = 0

    # Determine if modifications are enabled and ExifTool is available
    if (-not ($SessionConfig.ModifyFiles -and $SessionConfig.ExifToolPath)) {
        Write-Verbose "  Skipping modifications (ModifyFiles=$($SessionConfig.ModifyFiles), ExifToolPath=$($SessionConfig.ExifToolPath))"
        return @{ Processed = $processedCount; Skipped = $skippedCount } # Return zero counts
    }

    $resolvedExifToolPath = $SessionConfig.ExifToolPath # Already resolved path

    # --- Build Proposed Changes ---
    $originalExtension = $FileInfo.Extension; $originalFileNameBase = [System.IO.Path]::GetFileNameWithoutExtension($FileInfo.Name)
    $sanitizedNamePart = if ($ParsedData.Name) { Sanitize-Filename -InputString $ParsedData.Name } else { $null }
    $sanitizedLocationPart = if ($SessionConfig.UpdateLocation -and $ParsedData.Location) { Sanitize-Filename -InputString $ParsedData.Location -MaxLength 50 } else { $null }
    $ratingPart = if ($SessionConfig.UpdateRating -and $ParsedData.Rating -ne $null) { "Rating$($ParsedData.Rating)" } else { $null } # Prefix Rating

    $newNameParts = [System.Collections.ArrayList]::new()
    if ($sanitizedNamePart) { [void]$newNameParts.Add($sanitizedNamePart) } else { [void]$newNameParts.Add($originalFileNameBase) }
    if ($sanitizedLocationPart) { [void]$newNameParts.Add($sanitizedLocationPart) }
    if ($ratingPart) { [void]$newNameParts.Add($ratingPart) }
    if ($newNameParts.Count -eq 0) { [void]$newNameParts.Add($originalFileNameBase) } # Failsafe

    $newNameBase = $newNameParts -join '_'; $newName = "{0}{1}" -f $newNameBase, $originalExtension; $newPath = Join-Path -Path $FileInfo.DirectoryName -ChildPath $newName

    # Determine if changes are actually proposed
    $isRenameProposed = ($newName -ne $FileInfo.Name)
    $anyUpdateSwitch = $SessionConfig.UpdateTitle -or $SessionConfig.UpdateAuthor -or $SessionConfig.UpdateSubject -or $SessionConfig.UpdateTags -or $SessionConfig.UpdateRating -or $SessionConfig.UpdateLocation -or $SessionConfig.UpdateDescription
    $hasDataForProposedMetadata = ($SessionConfig.UpdateTitle -and $ParsedData.Name) -or
                                  ($SessionConfig.UpdateAuthor -and $SessionConfig.AuthorName) -or
                                  ($SessionConfig.UpdateSubject -and $ParsedData.Name) -or
                                  ($SessionConfig.UpdateTags -and $ParsedData.Tags.Count -gt 0) -or
                                  ($SessionConfig.UpdateRating -and $ParsedData.Rating -ne $null) -or
                                  ($SessionConfig.UpdateDescription -and $ParsedData.Description) -or
                                  ($SessionConfig.UpdateLocation -and $ParsedData.Location)
    $isMetadataUpdateProposed = $anyUpdateSwitch -and $hasDataForProposedMetadata

    # --- Propose and Confirm/Execute ---
    $proceedWithModify = $false
    if ($isRenameProposed -or $isMetadataUpdateProposed) {
        Write-Verbose "  Original Name: '$($FileInfo.Name)'"
        Write-Verbose "  New Name Base Parts: $($newNameParts -join ', ')"
        Write-Verbose "  Proposed New Full Name: '$newName'"

        $isConflict = $isRenameProposed -and (Test-Path -LiteralPath $newPath -PathType Leaf)

        # Build proposal message
        Write-Host "`n--- Proposed Changes for '$($FileInfo.Name)' ---" -ForegroundColor Yellow
        $renameMsg = if (-not $isRenameProposed) { "'$($FileInfo.Name)' (Metadata only)" } else { "'$($FileInfo.Name)' -> '$newName'" }
        $metaMsgs = @()
        if ($SessionConfig.UpdateTitle -and $ParsedData.Name) { $metaMsgs += "Title" }
        if ($SessionConfig.UpdateAuthor -and $SessionConfig.AuthorName) { $metaMsgs += "Author" }
        if ($SessionConfig.UpdateSubject -and $ParsedData.Name) { $metaMsgs += "Subject" }
        if ($SessionConfig.UpdateTags) { $metaMsgs += ($ParsedData.Tags.Count -gt 0) ? "Tags ($($ParsedData.Tags.Count))" : "Clear Tags" }
        if ($SessionConfig.UpdateRating -and $ParsedData.Rating -ne $null) { $metaMsgs += "Rating" }
        if ($SessionConfig.UpdateLocation -and $ParsedData.Location) { $metaMsgs += "Location Meta" }
        if ($SessionConfig.UpdateDescription -and $ParsedData.Description) { $metaMsgs += "Description" }
        $metaMsg = if ($metaMsgs) { " (" + ($metaMsgs -join ', ') + ")" } else { "" }

        if ($isConflict) { Write-Host "[CONFLICT] $renameMsg (Target exists!)" -ForegroundColor Red }
        else { Write-Host "$renameMsg$metaMsg" -ForegroundColor Cyan }
        Write-Host "---------------------------------------" -ForegroundColor Yellow

        # Confirm or proceed automatically
        if ($isConflict) { Write-Warning "Modification skipped due to filename conflict."; $skippedCount++ }
        elseif ($SessionConfig.ConfirmModifications) { $confirmInput = Read-Host "Proceed with changes? (y/N)"; if ($confirmInput -eq 'y') { $proceedWithModify = $true } else { Write-Host "Changes aborted by user." -ForegroundColor Yellow; $skippedCount++ } }
        else { Write-Host "Proceeding automatically." -ForegroundColor Yellow; $proceedWithModify = $true }

    } else { Write-Verbose "No changes proposed." }

    # --- Execute Modifications ---
    if ($proceedWithModify) {
        $currentFilePath = $FileInfo.FullName; $renameSuccess = $true; $metadataSuccess = $true

        # 1. Rename file if proposed
        if ($isRenameProposed) {
            try { Rename-Item -LiteralPath $currentFilePath -NewName $newName -EA Stop; Write-Host "[Renamed '$($FileInfo.Name)' -> '$newName']" -F DarkGray; $currentFilePath = $newPath }
            catch { $errMsg = "Failed rename '$($FileInfo.FullName)' -> '$newName': $($_.Exception.Message)"; Write-Warning $errMsg; [void]$GlobalRenameErrors.Add($errMsg); $renameSuccess = $false; $skippedCount++ }
        }

        # 2. Update metadata if proposed and rename didn't fail
        if ($renameSuccess -and $isMetadataUpdateProposed) {
            $metadataSuccess = Invoke-ExifToolUpdate -ResolvedExifToolPath $resolvedExifToolPath -CurrentFilePath $currentFilePath -ParsedData $ParsedData -SessionConfig $SessionConfig
            if (-not $metadataSuccess) { [void]$GlobalMetadataErrors.Add("Metadata update failed for '$currentFilePath'") }
        }

        # Increment processed count if rename OR metadata succeeded (or wasn't needed but rename happened)
        if (($isRenameProposed -and $renameSuccess) -or ($isMetadataUpdateProposed -and $metadataSuccess)) {
            if ($skippedCount -eq 0) { # Don't count as processed if skipped earlier
                 $processedCount++
            }
        } elseif ($isRenameProposed -and -not $renameSuccess) {
             # Already counted as skipped above
        } elseif ($isMetadataUpdateProposed -and -not $metadataSuccess) {
             $skippedCount++ # Count as skipped if ONLY metadata failed
        }

    }

    return @{ Processed = $processedCount; Skipped = $skippedCount }
}


# --- MODULAR HELPER: Process Initial Media Files ---
function Process-InitialMediaFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$SessionConfig,
        [Parameter(Mandatory=$true)]$ApiKey,
        [Parameter(Mandatory=$true)]$StartPrompt,
        [Parameter(Mandatory=$true)]$GlobalRenameErrors, # ArrayList
        [Parameter(Mandatory=$true)]$GlobalMetadataErrors # ArrayList
    )

    Write-Host "`nProcessing initial files in '$($SessionConfig.MediaFolder)'$($SessionConfig.RecurseFiles ? ' (Recursive)' : '') using StartPrompt..." -ForegroundColor Yellow
    Write-Host "Base Start Prompt: $StartPrompt" -ForegroundColor White

    $processedFileCount = 0; $skippedFileCount = 0
    $discoveredFiles = [System.Collections.ArrayList]::new()
    $supportedExtensionsMap = @{
        image    = @('.jpg','.jpeg','.png','.webp','.gif','.heic','.heif','.bmp','.tif','.tiff')
        video    = @('.mp4','.mpeg','.mov','.avi','.flv','.mpg','.webm','.wmv','.3gp','.3gpp','.mkv')
        audio    = @('.mp3','.wav','.ogg','.flac','.m4a','.aac','.wma')
        document = @('.txt','.pdf','.html','.htm','.json','.csv','.xml','.rtf','.md')
    }

    # Discover files, excluding the OutputFile if specified
    $excludePath = if ($SessionConfig.OutputFile) { Resolve-Path -LiteralPath $SessionConfig.OutputFile -ErrorAction SilentlyContinue } else { $null }
    foreach ($mediaType in $supportedExtensionsMap.Keys) {
        $found = Get-StartMediaFiles -FolderPath $SessionConfig.MediaFolder -Recurse:$SessionConfig.RecurseFiles -SupportedExtensions $supportedExtensionsMap[$mediaType] -MediaType $mediaType -ExcludePath $excludePath
        if ($found) { Write-Host "($($found.Count) starting $($mediaType) file(s) found)" -ForegroundColor Gray; $found.ForEach({ [void]$discoveredFiles.Add($_) }) }
    }

    if ($discoveredFiles.Count -eq 0) { Write-Warning "No supported files found in '$($SessionConfig.MediaFolder)'."; return $false } # Indicate no files processed

    # --- Process Each Discovered File ---
    $fileIndex = 0; $totalFiles = $discoveredFiles.Count
    Write-Progress -Activity "Processing Media Files" -Status "Starting..." -PercentComplete 0

    foreach ($fileInfo in $discoveredFiles) {
        $fileIndex++; $filePath = $fileInfo.FullName
        Write-Host "`nProcessing File $fileIndex of $totalFiles`: $($fileInfo.Name)" -ForegroundColor Cyan
        Write-Progress -Activity "Processing Media Files" -Status "Processing '$($fileInfo.Name)' ($fileIndex/$totalFiles)" -PercentComplete (($fileIndex / $totalFiles) * 100)

        # --- Read GPS and Modify Prompt ---
        $promptForThisFile = $StartPrompt; $gpsCoordsString = $null
        if ($SessionConfig.UpdateLocation -and $SessionConfig.ExifToolPath) {
            $gpsCoordsString = Get-GpsFromExif -FileInfo $fileInfo -ResolvedExifToolPath $SessionConfig.ExifToolPath
            if ($gpsCoordsString) {
                 $locationInstruction = "`n5. Based on coordinates ($gpsCoordsString), determine Location (City, State/Prov, Country). Prefix 'Location:'. Ex: Location: San Francisco, CA, USA"
                 $promptForThisFile += $locationInstruction; Write-Verbose "  Appended GPS location instruction to prompt."
            }
        } elseif ($SessionConfig.UpdateLocation) { Write-Warning "  Cannot read GPS (-UpdateLocation) - ExifTool not found or path invalid." }

        # --- API Call for this file ---
        $invokeParams = @{
            ApiKey              = $ApiKey; Model                 = $SessionConfig.Model; TimeoutSec          = $SessionConfig.TimeoutSec
            MaxRetries          = $SessionConfig.MaxRetries; InitialRetryDelaySec= $SessionConfig.InitialRetryDelaySec
            Prompt              = $promptForThisFile; InlineFilePaths       = @($filePath); ConversationHistory = @() # New history per file
        }
        if ($SessionConfig.GenerationConfig) { $invokeParams.GenerationConfig = $SessionConfig.GenerationConfig }
        Write-Host "[DEBUG] Sending Prompt (File: $($fileInfo.Name)):`n$($invokeParams.Prompt)" -ForegroundColor DarkYellow; Write-Host "Gemini is thinking..." -ForegroundColor DarkGray
        $timerJob = Start-Job -ScriptBlock { Start-Sleep -Seconds 3600 }; try { $apiResult = Invoke-GeminiApi @invokeParams } finally { Stop-Job -Job $timerJob -EA SilentlyContinue; Remove-Job -Job $timerJob -Force -EA SilentlyContinue; Write-Host "`r".PadRight([Console]::WindowWidth - 1); Write-Host "`r" -NoNewline }

        # --- Process Result ---
        if ($apiResult -and $apiResult.Success) {
            Write-Host "Gemini Response:" -ForegroundColor Green; Write-Host $apiResult.GeneratedText -ForegroundColor Green
            if ($SessionConfig.OutputFile) { try { "`n--- File '$($fileInfo.Name)' ($(Get-Date)) ---`nPROMPT:`n$($invokeParams.Prompt)`n`nRESPONSE:`n$($apiResult.GeneratedText)`n" | Out-File -FilePath $SessionConfig.OutputFile -Append -Encoding UTF8 -EA Stop; Write-Verbose "Appended response to log." } catch { Write-Warning "Failed append to '$($SessionConfig.OutputFile)': $($_.Exception.Message)" } }

            $parsedData = Parse-GeminiResponse -GeminiText $apiResult.GeneratedText

            # --- Attempt Modifications ---
            $modResult = Update-FileWithGeminiResults -FileInfo $fileInfo -ParsedData $parsedData -SessionConfig $SessionConfig -GlobalRenameErrors $GlobalRenameErrors -GlobalMetadataErrors $GlobalMetadataErrors
            $processedFileCount += $modResult.Processed
            $skippedFileCount += $modResult.Skipped

            # --- Save Parsed Results to CSV ---
            if ($SessionConfig.ResultsCsvFile) { Save-ParsedResultsToCsv -OriginalFileInfo $fileInfo -ParsedData $parsedData -ResultsCsvFilePath $SessionConfig.ResultsCsvFile }

        } else { # API Call Failed
             Write-Error "API call failed for '$($fileInfo.Name)'."
             if ($apiResult) { if ($apiResult.StatusCode) { Write-Error " Status: $($apiResult.StatusCode)" }; if ($apiResult.ResponseBody) { Write-Error " Body: $($apiResult.ResponseBody)" }; if ($apiResult.ErrorRecord) { Write-Error " Details: $($apiResult.ErrorRecord.Exception.Message)" } }
             else { Write-Error " Invoke-GeminiApi returned null." }
             if ($SessionConfig.OutputFile) { try { $errInfo = if($apiResult){ "Status: $($apiResult.StatusCode); Error: $($apiResult.ErrorRecord.Exception.Message); Body: $($apiResult.ResponseBody)" } else { "N/A" }; "`n--- File '$($fileInfo.Name)' ($(Get-Date)) - API ERROR ---`nPROMPT:`n$($invokeParams.Prompt)`n`nGemini ERROR:`n$errInfo`n--- End Error ---`n" | Out-File -FilePath $SessionConfig.OutputFile -Append -Encoding UTF8 -EA Stop; Write-Verbose "Appended API error to log." } catch { Write-Warning "Failed append API error to '$($SessionConfig.OutputFile)': $($_.Exception.Message)" } }
             $skippedFileCount++
        }

        # --- Delay ---
        if ($SessionConfig.FileDelaySec -gt 0 -and $fileIndex -lt $totalFiles) { Write-Verbose "Pausing for $($SessionConfig.FileDelaySec) second(s)..."; Start-Sleep -Seconds $SessionConfig.FileDelaySec }

    } # End foreach ($fileInfo in $discoveredFiles)

    Write-Progress -Activity "Processing Media Files" -Completed
    Write-Host "`n--- Finished Processing Initial Files ($processedFileCount files modified, $skippedFileCount files skipped) ---" -ForegroundColor Yellow
    return $true # Indicate files were processed
}


# --- MODULAR HELPER: Get Chat Input ---
function Get-ChatInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$SessionConfig,
        [Parameter(Mandatory=$true)][bool]$IsFirstInteractiveTurn
    )
    if ($IsFirstInteractiveTurn) {
        # --- Updated Command List with Descriptions ---
        Write-Host "Commands:" -ForegroundColor Cyan
        Write-Host "  /history      - Display conversation history." -ForegroundColor Cyan
        Write-Host "  /clear        - Clear conversation history." -ForegroundColor Cyan
        Write-Host "  /retry        - Retry the last failed API call." -ForegroundColor Cyan
        Write-Host "  /config       - Show current session settings." -ForegroundColor Cyan
        Write-Host "  /save         - Save history to CSV (if -CsvOutputFile specified)." -ForegroundColor Cyan
        Write-Host "  /media [path] - Add media (folder/file) for the next prompt. If no path, prompts interactively." -ForegroundColor Cyan
        Write-Host "  /generate ... - Generate an image via Vertex AI." -ForegroundColor Cyan
        Write-Host "  /generate_from <path> - Use Gemini to describe image(s) at <path>, then generate new image(s)." -ForegroundColor Cyan
        Write-Host "  /model [name] - Change the Gemini model. If no name, shows list." -ForegroundColor Cyan
        Write-Host "  /imagemodel [name] - Change the Vertex AI image generation model. If no name, shows list." -ForegroundColor Cyan
        Write-Host "  /exit         - Exit the chat session." -ForegroundColor Cyan
        Write-Host "Enter your first prompt:" -ForegroundColor Cyan
    }
    try {
        $input = Read-Host "`nYou"
        return $input
    } catch {
        Write-Warning "Input error occurred."
        return "/exit" # Treat input error as exit signal
    }
}

# --- MODULAR HELPER: Process API Result ---
function Process-ApiResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$ApiResult,
        [Parameter(Mandatory=$true)]$CurrentPromptInput,
        [Parameter(Mandatory=$true)]$SessionConfig,
        [Parameter(Mandatory=$true)]$ConversationHistory # Array
    )

    $updatedHistory = $ConversationHistory # Default to old history if API failed

    if ($ApiResult -and $ApiResult.Success) {
        Write-Host "`nGemini:" -F Green; Write-Host $ApiResult.GeneratedText -F Green
        $updatedHistory = $ApiResult.UpdatedConversationHistory # Get updated history
        Write-Verbose "History updated ($($updatedHistory.Count) turns)."
        # Log to file
        if ($SessionConfig.OutputFile) {
            try {
                $turnNumber = ($updatedHistory.Count / 2) # History includes both user and model turns
                $outputContent = "`n--- Turn $($turnNumber) ($(Get-Date)) ---`nYou:`n$CurrentPromptInput`n`nGemini:`n$($ApiResult.GeneratedText)`n"
                $outputContent | Out-File -FilePath $SessionConfig.OutputFile -Append -Encoding UTF8 -EA Stop
                Write-Verbose "Appended turn to log."
            } catch { Write-Warning "Failed append turn to '$($SessionConfig.OutputFile)': $($_.Exception.Message)" }
        }
    } else {
        # Error handling (already written by Invoke-GeminiApi or command handler)
        Write-Error "API call failed or was skipped." # Simple message here
        Write-Warning "History may not be updated correctly for this turn."
        # Log error to file
        if ($SessionConfig.OutputFile) {
             try {
                 $turnNumber = ($ConversationHistory.Count / 2) + 1 # Estimate next turn number
                 $statusCodeInfo = if($ApiResult){"Status: $($ApiResult.StatusCode)"}else{"N/A"}
                 $exceptionInfo = if($ApiResult -and $ApiResult.ErrorRecord){"Exception: $($ApiResult.ErrorRecord.Exception.Message)"}else{"N/A"}
                 $responseBodyInfo = if($ApiResult){"Body:`n$($ApiResult.ResponseBody)"}else{"Body: N/A"}
                 $errorContent="`n--- Turn $($turnNumber) ($(Get-Date)) - API ERROR ---`nYou:`n$CurrentPromptInput`n`nGemini ERROR:`n$statusCodeInfo`n$exceptionInfo`n$responseBodyInfo`n--- End Error ---`n"
                 $errorContent|Out-File -FilePath $SessionConfig.OutputFile -Append -Encoding UTF8 -EA Stop
                 Write-Verbose "Appended API error to log."
             }catch{Write-Warning "Failed append API error to '$($SessionConfig.OutputFile)': $($_.Exception.Message)"}
         }
    }
    return $updatedHistory
}


# --- MODULAR HELPER: Ensure Vertex AI Config ---
function Ensure-VertexAiConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ref]$SessionConfigRef # Pass hashtable by reference
    )
    $config = $SessionConfigRef.Value # Dereference to work with the copy
    $configUpdated = $false

    if (-not ($config.VertexProjectId -and $config.VertexLocationId -and $config.VertexDefaultOutputFolder)) {
        Write-Warning "Vertex AI parameters are required for this command."
        if ([string]::IsNullOrWhiteSpace($config.VertexProjectId)) {
            $projId = Read-Host "Enter Google Cloud Project ID for Vertex AI"
            if ([string]::IsNullOrWhiteSpace($projId)) { Write-Error "Vertex Project ID is required."; return $false }
            $config.VertexProjectId = $projId; $configUpdated = $true
        }
        if ([string]::IsNullOrWhiteSpace($config.VertexLocationId)) {
            $locId = Read-Host "Enter Vertex AI Location ID (e.g., us-central1)"
            if ([string]::IsNullOrWhiteSpace($locId)) { Write-Error "Vertex Location ID is required."; return $false }
            $config.VertexLocationId = $locId; $configUpdated = $true
        }
        if ([string]::IsNullOrWhiteSpace($config.VertexDefaultOutputFolder)) {
            $outFolder = Read-Host "Enter default folder path for generated images"
            if ([string]::IsNullOrWhiteSpace($outFolder)) { Write-Error "Vertex Default Output Folder is required."; return $false }
            # Validate/Create Folder
            try {
                 if (-not (Test-Path -LiteralPath $outFolder -PathType Container)) { Write-Warning "Creating output folder: $outFolder"; New-Item -Path $outFolder -ItemType Directory -Force -EA Stop | Out-Null }
                 $config.VertexDefaultOutputFolder = $outFolder; $configUpdated = $true
            } catch { Write-Error "Failed to create output folder '$outFolder'. Cannot proceed. Error: $($_.Exception.Message)"; return $false }
        }

        # If config was updated, write back to the original hashtable via reference
        if ($configUpdated) {
             $SessionConfigRef.Value = $config
             Write-Host "Vertex AI configuration updated for this session." -ForegroundColor Green
        }
    }
    # Return true if config is now valid
    return ($config.VertexProjectId -and $config.VertexLocationId -and $config.VertexDefaultOutputFolder)
}

# --- MODULAR HELPER: Prompt for Media Path (/media interactive) ---
function Prompt-ForMediaInput {
    [CmdletBinding()]
    param(
        # Output parameters using references
        [Parameter(Mandatory=$true)][ref]$ImageFolderRef,
        [Parameter(Mandatory=$true)][ref]$VideoFolderRef,
        [Parameter(Mandatory=$true)][ref]$RecurseRef,
        [Parameter(Mandatory=$true)][ref]$InlineFilePathsRef
    )
    $rawMediaInput = Read-Host "Enter Media Folder Path or File Path"
    $mediaAdded = $false
    if (-not [string]::IsNullOrWhiteSpace($rawMediaInput)) {
        $mediaInput = $rawMediaInput.Trim('"').Trim("'")
        if (Test-Path -LiteralPath $mediaInput -PathType Container) {
            $ImageFolderRef.Value = $mediaInput; $VideoFolderRef.Value = $mediaInput # Search both
            Write-Host "(Will search folder: '$mediaInput')" -ForegroundColor Gray
            $recurseMedia = Read-Host "Search recursively? (y/N)"; if ($recurseMedia.Trim().ToLowerInvariant() -eq 'y') { $RecurseRef.Value = $true }
            $mediaAdded = $true
        } elseif (Test-Path -LiteralPath $mediaInput -PathType Leaf) {
            $InlineFilePathsRef.Value = @($mediaInput); Write-Host "(Will use file: $mediaInput)" -ForegroundColor Gray
            $mediaAdded = $true
        } else { Write-Warning "Media path not found or invalid: $mediaInput" }
    }
    return $mediaAdded # Return true if media was successfully identified
}


# --- MODULAR HELPER: Handle Chat Commands ---
function Handle-ChatCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$TrimmedInput,
        [Parameter(Mandatory=$true)][ref]$SessionConfigRef, # Use ref to allow modification (e.g., models)
        [Parameter(Mandatory=$true)][ref]$ConversationHistoryRef, # Use ref to allow /clear
        [Parameter(Mandatory=$true)]$LastApiResult, # For /retry
        [Parameter(Mandatory=$true)][string]$LastUserPrompt, # For /retry
        [Parameter()]$LastApiResult, # For /retry - Removed Mandatory=$true
        [Parameter()]$LastUserPrompt, # For /retry - Removed Mandatory=$true
        [Parameter(Mandatory=$true)]$ApiKey, # Needed for /generate_from
        # --- Turn-specific media variables (passed by ref for /media) ---
        [Parameter(Mandatory=$true)][ref]$CurrentImageFolderRef,
        [Parameter(Mandatory=$true)][ref]$CurrentVideoFolderRef,
        [Parameter(Mandatory=$true)][ref]$CurrentRecurseRef,
        [Parameter(Mandatory=$true)][ref]$CurrentInlineFilePathsRef
    )

    # Dereference config and history for easier access (changes need to go back via ref)
    $sessionConfig = $SessionConfigRef.Value
    $conversationHistory = $ConversationHistoryRef.Value

    # Define Model Lists for Interactive Selection
    # Updated Gemini Model List
    $geminiModelOptions = @(
        'gemini-1.5-pro'
        'gemini-1.5-flash'
        'gemini-1.5-flash-8b'
        'gemini-2.0-flash'
        'gemini-2.0-flash-exp-image-generation'
        'gemini-2.0-flash-lite'
        'gemini-2.5-pro-preview-03-25'
        'gemini-2.5-flash-preview-04-17'
    )
    $imagenModelOptions = @('imagen-3.0-generate-002', 'imagen-3.0-fast-generate-001', 'imagegeneration@006', 'imagegeneration@005') # Updated Imagen Model List

    $commandResult = @{
        CommandExecuted = $false # Did we successfully run a known command?
        SkipApiCall     = $false # Should the main loop skip the Gemini API call this turn?
        ExitSession     = $false # Should the main loop exit?
        PromptOverride  = $null  # If command provides the prompt (e.g., /media)
        MediaAdded      = $false # Did the /media command add media this turn?
    }

    if (-not $TrimmedInput.StartsWith('/')) {
        return $commandResult # Not a command
    }

    # --- Command Processing ---
    switch -Regex ($TrimmedInput) {
        '^/(history|hist)$' {
            Write-Host "`n--- Conversation History ---" -ForegroundColor Yellow
            if ($conversationHistory.Count -eq 0) { Write-Host "(History is empty)" -ForegroundColor Gray }
            else {
                for ($i = 0; $i -lt $conversationHistory.Count; $i++) {
                    $turn = $conversationHistory[$i]; $role = $turn.role.ToUpper()
                    $text = ($turn.parts | Where-Object { $_.text } | Select-Object -ExpandProperty text) -join "`n"
                    $mediaInfo = ""
                    if ($turn.parts | Where-Object { $_.inline_data }) { $mediaInfo = " (Inline Media)" }
                    elseif ($turn.parts | Where-Object { $_.file_data }) { $mediaInfo = " (File API Media)" }
                    Write-Host "[$role] $($text)$mediaInfo" -ForegroundColor (if ($role -eq 'USER') { [ConsoleColor]::White } else { [ConsoleColor]::Green })
                }
            }
            Write-Host "--------------------------" -ForegroundColor Yellow
            $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $true
        }
        '^/clear$' {
            Write-Host "`nClearing conversation history." -ForegroundColor Yellow
            $ConversationHistoryRef.Value = @() # Clear history via ref
            # Note: Need to clear last prompt/result in the *calling* scope as well if needed for /retry consistency
            $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $true
        }
        '^/retry$' {
            if ($LastApiResult -ne $null -and -not $LastApiResult.Success -and $LastUserPrompt) {
                Write-Host "`nRetrying last failed API call..." -ForegroundColor Yellow
                Write-Host "Retrying prompt: $LastUserPrompt" -ForegroundColor Gray
                $commandResult.PromptOverride = $LastUserPrompt # Tell main loop to use this prompt
                $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $false # Allow API call
            } else {
                Write-Warning "No failed API call to retry, or last prompt missing."
                $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $true
            }
        }
        '^/config$' {
            Write-Host "`n--- Session Configuration ---" -ForegroundColor Yellow
            $sessionConfig.GetEnumerator() | Sort-Object Name | ForEach-Object { Write-Host ("{0,-25}: {1}" -f $_.Name, ($_.Value | Out-String -Stream).Trim()) }
            Write-Host "---------------------------" -ForegroundColor Yellow
            $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $true
        }
        '^/save$' {
            Write-Host "`nAttempting to save conversation history..." -ForegroundColor Yellow
            if ($sessionConfig.CsvOutputFile -and $conversationHistory.Count -gt 0) { Save-ChatToCsv -ConversationHistory $conversationHistory -CsvOutputFile $sessionConfig.CsvOutputFile }
            elseif (-not $sessionConfig.CsvOutputFile) { Write-Warning "Cannot save: No -CsvOutputFile specified." }
            else { Write-Warning "Cannot save: Conversation history is empty." }
            $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $true
        }
        '^/exit$' {
            Write-Host "Exiting." -ForegroundColor Cyan
            $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $true; $commandResult.ExitSession = $true
        }
        '^/media(\s+(.+))?$' {
            # Clear any previous media selections from this turn attempt
            $CurrentImageFolderRef.Value = $null; $CurrentVideoFolderRef.Value = $null; $CurrentRecurseRef.Value = $false; $CurrentInlineFilePathsRef.Value = $null
            $mediaPathProvided = $null; $mediaAddedSuccessfully = $false

            if ($Matches[2]) { # Path provided with command
                $mediaPathProvided = $Matches[2].Trim().Trim('"').Trim("'")
                Write-Host "`nProcessing media path from command: '$mediaPathProvided'" -ForegroundColor Yellow
                if (Test-Path -LiteralPath $mediaPathProvided -PathType Container) {
                    $CurrentImageFolderRef.Value = $mediaPathProvided; $CurrentVideoFolderRef.Value = $mediaPathProvided
                    Write-Host "(Will search folder: '$mediaPathProvided')" -ForegroundColor Gray
                    $r = Read-Host "Search recursively? (y/N)"; if ($r -eq 'y') { $CurrentRecurseRef.Value = $true }
                    $mediaAddedSuccessfully = $true
                } elseif (Test-Path -LiteralPath $mediaPathProvided -PathType Leaf) {
                    $CurrentInlineFilePathsRef.Value = @($mediaPathProvided); Write-Host "(Will use file: $mediaPathProvided)" -ForegroundColor Gray
                    $mediaAddedSuccessfully = $true
                } else { Write-Warning "Media path provided not found or invalid: '$mediaPathProvided'" }
            } else { # Interactive prompt
                Write-Host "`nAdding media for the next prompt..." -ForegroundColor Yellow
                $mediaAddedSuccessfully = Prompt-ForMediaInput -ImageFolderRef $CurrentImageFolderRef -VideoFolderRef $CurrentVideoFolderRef -RecurseRef $CurrentRecurseRef -InlineFilePathsRef $CurrentInlineFilePathsRef
            }

            if ($mediaAddedSuccessfully) {
                $commandResult.MediaAdded = $true # Signal that media was added
                Write-Host "Media added. Enter the text prompt associated with this media:" -ForegroundColor Cyan
                $promptForMedia = Read-Host " You (prompt for media)"
                $commandResult.PromptOverride = $promptForMedia # Tell main loop to use this prompt
                $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $false # Allow API call with this media/prompt
            } else {
                # No valid media added
                $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $true # Skip API call
            }
        }
        '^/model(\s+(\S+))?$' {
             Write-Host "`nCurrent Gemini model: '$($sessionConfig.Model)'" -ForegroundColor Gray
             if ($Matches[2]) { $newModel = $Matches[2].Trim(); $sessionConfig.Model = $newModel; Write-Host "Model changed to '$newModel'." -F Yellow }
             else {
                 Write-Host "Available Gemini models:" -F Cyan; $geminiModelOptions.ForEach({Write-Host "  $($_)" -F Cyan}) # Simpler list for brevity
                 $modelInput = Read-Host "Enter model name"; if ($modelInput) { $sessionConfig.Model = $modelInput.Trim(); Write-Host "Model changed to '$($sessionConfig.Model)'." -F Yellow } else { Write-Warning "No change."}
             }
             $SessionConfigRef.Value = $sessionConfig # Write changes back
             $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $true
        }
        '^/imagemodel(\s+(\S+))?$' {
             if (-not (Ensure-VertexAiConfig -SessionConfigRef $SessionConfigRef)) { $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $true; return $commandResult } # Ensure config, exit if failed
             $sessionConfig = $SessionConfigRef.Value # Re-read config after potential update
             Write-Host "`nCurrent Vertex Image model: '$($sessionConfig.VertexImageModel)'" -ForegroundColor Gray
             if ($Matches[2]) { $newModel = $Matches[2].Trim(); $sessionConfig.VertexImageModel = $newModel; Write-Host "Vertex Image model changed to '$newModel'." -F Yellow }
             else {
                 Write-Host "Available Vertex Imagen models:" -F Cyan; $imagenModelOptions.ForEach({Write-Host "  $($_)" -F Cyan}) # Simpler list
                 $modelInput = Read-Host "Enter model name"; if ($modelInput) { $sessionConfig.VertexImageModel = $modelInput.Trim(); Write-Host "Vertex Image model changed to '$($sessionConfig.VertexImageModel)'." -F Yellow } else { Write-Warning "No change."}
             }
             $SessionConfigRef.Value = $sessionConfig # Write changes back
             $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $true
        }
        '/(generate|image)\s+(.+)' {
            if (-not (Ensure-VertexAiConfig -SessionConfigRef $SessionConfigRef)) { $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $true; return $commandResult }
            $sessionConfig = $SessionConfigRef.Value # Re-read config
            $imageGenPrompt = $Matches[2].Trim(); $cmdName = $Matches[1]
            Write-Host "Image Generation command detected: /$cmdName" -F Magenta; Write-Host "Prompt: $imageGenPrompt" -F Magenta
            # Prepare and call Start-VertexImageGeneration
            $vertexParams = @{ ProjectId = $sessionConfig.VertexProjectId; LocationId = $sessionConfig.VertexLocationId; Prompt = $imageGenPrompt; OutputFolder = $sessionConfig.VertexDefaultOutputFolder; ModelId = $sessionConfig.VertexImageModel }
            if ($sessionConfig.Verbose) { $vertexParams.Verbose = $true }
            Start-VertexImageGeneration @vertexParams
            $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $true
        }
        '^/generate_from\s+(.+)' {
            if (-not (Ensure-VertexAiConfig -SessionConfigRef $SessionConfigRef)) { $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $true; return $commandResult }
            $sessionConfig = $SessionConfigRef.Value # Re-read config
            $inputPath = $Matches[1].Trim().Trim('"').Trim("'")
            $sourceImagePaths = [System.Collections.ArrayList]::new()

            # Validate input path and get image file(s)
            if (Test-Path -LiteralPath $inputPath -PathType Leaf) { [void]$sourceImagePaths.Add($inputPath); Write-Host "`n--- Generate From Image File: '$inputPath' ---" -F Yellow }
            elseif (Test-Path -LiteralPath $inputPath -PathType Container) { $imgExt = @('.jpg','.jpeg','.png','.webp','.gif','.heic','.heif','.bmp','.tif','.tiff'); $found = Get-ChildItem -LiteralPath $inputPath -File | Where-Object {$imgExt -contains $_.Extension.ToLowerInvariant()}; if ($found) { $found | ForEach-Object {[void]$sourceImagePaths.Add($_.FullName)}; Write-Host "`n--- Generate From Folder: '$inputPath' ($($found.Count) image(s)) ---" -F Yellow } else { Write-Error "No supported images found in folder '$inputPath'." } }
            else { Write-Error "Path not found or invalid: '$inputPath'" }

            if ($sourceImagePaths.Count -eq 0) { $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $true; return $commandResult }

            # Loop through images
            $imageIndex = 0; foreach ($currentImagePath in $sourceImagePaths) {
                $imageIndex++; Write-Host "`nProcessing image $imageIndex of $($sourceImagePaths.Count): '$currentImagePath'" -F Cyan
                # Describe with Gemini
                $descPrompt = "Describe this image in vivid detail for generating a similar image with an AI image generator."
                Write-Host "Asking Gemini to describe image..." -F DarkGray
                $descParams = @{ ApiKey=$ApiKey; Model=$sessionConfig.Model; Prompt=$descPrompt; InlineFilePaths=@($currentImagePath); ConversationHistory=@(); TimeoutSec=$sessionConfig.TimeoutSec; MaxRetries=$sessionConfig.MaxRetries; InitialRetryDelaySec=$sessionConfig.InitialRetryDelaySec }
                if ($sessionConfig.GenerationConfig) { $descParams.GenerationConfig = $sessionConfig.GenerationConfig }
                $descResult = Invoke-GeminiApi @descParams
                if (-not $descResult.Success) { Write-Error "Failed to get description from Gemini for '$currentImagePath'. Skipping generation."; continue }
                $genDesc = $descResult.GeneratedText; Write-Host "Gemini Description:" -F Green; Write-Host $genDesc -F Green
                # Generate with Vertex
                Write-Host "`nGenerating image based on description..." -F Yellow
                $vertexParams = @{ ProjectId=$sessionConfig.VertexProjectId; LocationId=$sessionConfig.VertexLocationId; Prompt=$genDesc; OutputFolder=$sessionConfig.VertexDefaultOutputFolder; ModelId=$sessionConfig.VertexImageModel }
                if ($sessionConfig.Verbose) { $vertexParams.Verbose = $true }
                Start-VertexImageGeneration @vertexParams
                if ($sessionConfig.FileDelaySec -gt 0 -and $imageIndex -lt $sourceImagePaths.Count) { Start-Sleep -Seconds $sessionConfig.FileDelaySec }
            }
            $commandResult.CommandExecuted = $true; $commandResult.SkipApiCall = $true
        }
        default { # Handle unrecognized commands
            Write-Warning "Unrecognized command: '$trimmedInput'. Type '/exit' to quit or enter a prompt."
            $commandResult.CommandExecuted = $false; $commandResult.SkipApiCall = $true # Treat as no-op, don't call API
        }
    } # End Switch

    return $commandResult
}


# --- Main Chat Function ---
function Start-GeminiChat {
    [CmdletBinding()]
    param(
        # --- Parameters (identical to original script v3.5.11) ---
        [Parameter(Mandatory=$true, HelpMessage = "Your Google Gemini API Key.")] [string]$ApiKey,
        [Parameter(HelpMessage = "The Gemini model to use.")] [string]$Model = 'gemini-1.5-pro-latest',
        [Parameter(HelpMessage = "Optional hashtable for generation configuration.")] [hashtable]$GenerationConfig,
        [Parameter(HelpMessage = "Timeout for API requests in seconds.")] [int]$TimeoutSec = 300,
        [Parameter(HelpMessage = "Max retries on HTTP 429 errors within API calls.")] [ValidateRange(0, 5)] [int]$MaxRetries = 3,
        [Parameter(HelpMessage = "Initial delay for HTTP 429 retries (seconds).")] [ValidateRange(1, 60)] [int]$InitialRetryDelaySec = 2,
        [Parameter(HelpMessage = "Delay in seconds between processing each file when using -MediaFolder.")] [ValidateRange(0, 60)] [int]$FileDelaySec = 1,
        [Parameter(HelpMessage = "Optional prompt for the first turn. REQUIRED if -MediaFolder is used.")] [string]$StartPrompt,
        [Parameter(HelpMessage = "Optional folder containing media for the first turn (processed one-by-one).")] [ValidateScript({ Test-Path -Path $_ -PathType Container })] [string]$MediaFolder,
        [Parameter(HelpMessage = "Recurse media folder.")] [switch]$RecurseFiles,
        [Parameter(HelpMessage = "Enable renaming/updating initial files based on response. Requires -MediaFolder & ExifTool.")] [switch]$ModifyFiles,
        [Parameter(HelpMessage = "If specified with -ModifyFiles, requires user confirmation before applying changes.")] [switch]$Confirm,
        [Parameter(HelpMessage = "Update 'Title' metadata (requires -ModifyFiles).")] [switch]$UpdateTitle,
        [Parameter(HelpMessage = "Replace 'Creator'/'Artist' metadata (requires -ModifyFiles, -AuthorName).")] [switch]$UpdateAuthor,
        [Parameter(Mandatory = $false, HelpMessage = "Author name for -UpdateAuthor.")] [string]$AuthorName,
        [Parameter(HelpMessage = "Update 'Comment' metadata from Title (requires -ModifyFiles).")] [switch]$UpdateSubject,
        [Parameter(HelpMessage = "Parse 'Tags:'/'Keywords:' and overwrite metadata (requires -ModifyFiles & ExifTool).")] [switch]$UpdateTags,
        [Parameter(HelpMessage = "Parse 'Rating:' and update metadata/append to filename (requires -ModifyFiles).")] [switch]$UpdateRating,
        [Parameter(HelpMessage = "Enables location processing (GPS read, AI prompt, Filename/Meta update). Requires -ModifyFiles & ExifTool.")] [switch]$UpdateLocation,
        [Parameter(HelpMessage = "Parse 'Description:' and update metadata (requires -ModifyFiles).")] [switch]$UpdateDescription,
        [Parameter(HelpMessage="Optional. Full path to exiftool.exe if not in system PATH.")] [string]$ExifToolPath,
        [Parameter(HelpMessage = "Optional file to append Gemini prompts and responses.")] [string]$OutputFile,
        [Parameter(HelpMessage="Google Cloud Project ID for Vertex AI Image Generation.")] [string]$VertexProjectId,
        [Parameter(HelpMessage="Google Cloud Location ID (e.g., 'us-central1') for Vertex AI.")] [string]$VertexLocationId,
        [Parameter(HelpMessage="Default output folder for Vertex AI generated images.")] [string]$VertexDefaultOutputFolder,
        [Parameter(HelpMessage="The Vertex AI Imagen model ID (e.g., 'imagegeneration@006').")] [string]$VertexImageModel = 'imagegeneration@006',
        [Parameter(HelpMessage="Optional file path to export the full conversation history as a CSV file upon exiting.")] [string]$CsvOutputFile,
        [Parameter(HelpMessage="Optional file path to save the parsed Gemini results for each processed file as a CSV.")] [string]$ResultsCsvFile
    )

    # --- Verbose Preference Handling ---
    $originalVerbosePreference = $VerbosePreference
    if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { $VerbosePreference = 'Continue'; Write-Host "[Start-GeminiChat] Verbose logging enabled." -ForegroundColor DarkGray }

    # --- API Key Check (Prompt if missing) ---
    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        Write-Host "API Key is required." -ForegroundColor Yellow
        try {
            $secureApiKey = Read-Host "Enter your Google Gemini API Key" -AsSecureString
            if ($secureApiKey.Length -gt 0) { $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureApiKey); $ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr); [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
            else { Write-Error "API Key cannot be empty."; return }
        } catch { Write-Error "Failed to read API Key: $($_.Exception.Message)"; return }
        # Update BoundParameters if Key was prompted - important for Initialize function
        $PSCmdlet.MyInvocation.BoundParameters['ApiKey'] = $ApiKey
    }

    # --- Initialize Session ---
    $sessionConfig = Initialize-GeminiChatSession -BoundParameters $PSCmdlet.MyInvocation.BoundParameters -Invocation $PSCmdlet.MyInvocation
    if (-not $sessionConfig) { Write-Error "Session initialization failed."; return } # Exit if init failed

    # --- Initialize Chat State ---
    $conversationHistory = @()
    $lastUserPrompt = $null
    $lastApiResult = $null
    $globalRenameErrors = [System.Collections.ArrayList]::new()
    $globalMetadataErrors = [System.Collections.ArrayList]::new()
    $isFirstTurn = $true

    # --- Main Chat Loop ---
    try {
        while ($true) {
            # --- Reset Turn Variables ---
            $currentPromptInput = $null; $apiResult = $null
            $currentImageFolder = $null; $currentVideoFolder = $null; $currentRecurse = $false; $currentInlineFilePaths = $null
            $mediaAddedThisTurn = $false # Reset flag

            # --- First Turn Logic ---
            if ($isFirstTurn) {
                $isFirstTurn = $false # Mark as processed
                if ($sessionConfig.MediaFolder) {
                    # Process initial files; $true indicates files were processed or attempted
                    if (Process-InitialMediaFiles -SessionConfig $sessionConfig -ApiKey $ApiKey -StartPrompt $StartPrompt -GlobalRenameErrors $globalRenameErrors -GlobalMetadataErrors $globalMetadataErrors) {
                        continue # Move to the next iteration (prompt for next turn)
                    } else {
                         Write-Warning "Initial file processing failed or found no files. Proceeding to interactive prompt."
                         # Fall through to interactive prompt
                    }
                } elseif ($StartPrompt) {
                    # StartPrompt provided without MediaFolder
                    $currentPromptInput = $StartPrompt
                    Write-Host "`nYou (Start): $currentPromptInput" -ForegroundColor White
                    # Fall through to API call section below
                } else {
                    # Fully interactive start
                    $currentPromptInput = Get-ChatInput -SessionConfig $sessionConfig -IsFirstInteractiveTurn $true
                    if ([string]::IsNullOrWhiteSpace($currentPromptInput)) { continue } # Skip if user entered nothing
                    if ($currentPromptInput.Trim().ToLowerInvariant() -eq '/exit') { Write-Host "Exiting." -F Cyan; break }
                    # Fall through to command handling / API call section below
                }
            } else {
                # --- Subsequent Turns ---
                $currentPromptInput = Get-ChatInput -SessionConfig $sessionConfig -IsFirstInteractiveTurn $false
                if ([string]::IsNullOrWhiteSpace($currentPromptInput)) { continue } # Skip if user entered nothing
                if ($currentPromptInput.Trim().ToLowerInvariant() -eq '/exit') { Write-Host "Exiting." -F Cyan; break }
            }

            # --- Handle Commands ---
            $commandResult = Handle-ChatCommand `
                -TrimmedInput $currentPromptInput.Trim() `
                -SessionConfigRef ([ref]$sessionConfig) `
                -ConversationHistoryRef ([ref]$conversationHistory) `
                -LastApiResult $lastApiResult `
                -LastUserPrompt $lastUserPrompt `
                -ApiKey $ApiKey `
                -CurrentImageFolderRef ([ref]$currentImageFolder) `
                -CurrentVideoFolderRef ([ref]$currentVideoFolder) `
                -CurrentRecurseRef ([ref]$currentRecurse) `
                -CurrentInlineFilePathsRef ([ref]$currentInlineFilePaths)

            # Update state based on command result
            $currentPromptInput = if ($commandResult.PromptOverride -ne $null) { $commandResult.PromptOverride } else { $currentPromptInput }
            $mediaAddedThisTurn = $commandResult.MediaAdded

            # Special case: clear command needs to clear last prompt/result here
            if ($currentPromptInput.Trim() -eq '/clear') {
                $lastUserPrompt = $null; $lastApiResult = $null
            }

            if ($commandResult.ExitSession) { break }
            if ($commandResult.SkipApiCall) { Write-Host "------------------------------------------" -ForegroundColor Cyan; continue }

            # --- Make API Call ---
            if ($currentPromptInput -ne $null) {
                $lastUserPrompt = $currentPromptInput # Store before calling API

                $invokeParams = @{
                    ApiKey              = $ApiKey; Model                 = $sessionConfig.Model
                    TimeoutSec          = $sessionConfig.TimeoutSec; MaxRetries          = $sessionConfig.MaxRetries
                    InitialRetryDelaySec= $sessionConfig.InitialRetryDelaySec; Prompt              = $currentPromptInput
                    ConversationHistory = $conversationHistory
                }
                if ($sessionConfig.GenerationConfig) { $invokeParams.GenerationConfig = $sessionConfig.GenerationConfig }
                if ($mediaAddedThisTurn) { # Only add media if /media was used this turn
                    if ($currentImageFolder) { $invokeParams.ImageFolder = $currentImageFolder }
                    if ($currentVideoFolder) { $invokeParams.VideoFolder = $currentVideoFolder }
                    if ($currentRecurse) { $invokeParams.Recurse = $true }
                    if ($currentInlineFilePaths) { $invokeParams.InlineFilePaths = $currentInlineFilePaths }
                }

                $turnNumber = ($conversationHistory.Count / 2) + 1
                $debugMsg = "[DEBUG] Sending Prompt (Turn $turnNumber):`n$($invokeParams.Prompt)$($mediaAddedThisTurn ? "`n(With Media)" : "`")"
                Write-Host $debugMsg -ForegroundColor DarkYellow
                Write-Host "Gemini is thinking..." -ForegroundColor DarkGray

                $timerJob = Start-Job -ScriptBlock { Start-Sleep -Seconds 3600 }
                try { $apiResult = Invoke-GeminiApi @invokeParams; $lastApiResult = $apiResult } # Store result for /retry
                finally { Stop-Job -Job $timerJob -EA SilentlyContinue; Remove-Job -Job $timerJob -Force -EA SilentlyContinue; Write-Host "`r".PadRight([Console]::WindowWidth - 1); Write-Host "`r" -NoNewline }

                # --- Process API Result ---
                $conversationHistory = Process-ApiResult -ApiResult $apiResult -CurrentPromptInput $currentPromptInput -SessionConfig $sessionConfig -ConversationHistory $conversationHistory

                 # Reset turn media vars *after* processing result
                 $currentImageFolder = $null; $currentVideoFolder = $null; $currentRecurse = $false; $currentInlineFilePaths = $null
                 $mediaAddedThisTurn = $false

                Write-Host "------------------------------------------" -ForegroundColor Cyan
            } # End if ($currentPromptInput -ne $null)

        } # End while ($true)

    } finally {
        # --- Final Summary and Cleanup ---
        if ($globalRenameErrors.Count -gt 0) { Write-Warning "$($globalRenameErrors.Count) rename error(s):"; $globalRenameErrors | ForEach-Object { Write-Warning "- $_" } }
        if ($globalMetadataErrors.Count -gt 0) { Write-Warning "$($globalMetadataErrors.Count) metadata error(s):"; $globalMetadataErrors | ForEach-Object { Write-Warning "- $_" } }

        if ($sessionConfig.CsvOutputFile -and $conversationHistory.Count -gt 0) { Save-ChatToCsv -ConversationHistory $conversationHistory -CsvOutputFile $sessionConfig.CsvOutputFile }
        elseif ($sessionConfig.CsvOutputFile) { Write-Warning "Final CSV export skipped: History empty." }

        Write-Host "`nExiting Gemini chat session." -ForegroundColor Cyan
        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose "[Start-GeminiChat] Restoring original `$VerbosePreference ('$originalVerbosePreference')."; $VerbosePreference = $originalVerbosePreference }
    }

    return $conversationHistory
}


# --- Example Call Section (Minimal changes, ensure variables are set) ---

# Define default values for example calls.
if (-not (Get-Variable -Name 'examplePrompt' -ErrorAction SilentlyContinue)) { $examplePrompt = @"
No other text, Analyze the provided file:
1. Name: (Suggest emotional descriptive filename, 5-10 words, underscores for spaces)
2. Description: (Suggest emotional description, 100-500 words)
3. Rating: (Suggest 0-5 quality rating)
4. Tags: (Suggest 30-50 keywords: main subject, elements, location, actions, concepts, demographics, technical, format)
"@ }
if (-not (Get-Variable -Name 'myMediaFolder' -ErrorAction SilentlyContinue)) { $myMediaFolder = '.\Review_Photos'; Write-Warning "Defaulting `$myMediaFolder='$myMediaFolder'."; if (-not (Test-Path $myMediaFolder)) { New-Item -Path $myMediaFolder -ItemType Directory -Force > $null } }
if (-not (Get-Variable -Name 'myLogFile' -ErrorAction SilentlyContinue)) { $myLogFile = Join-Path $myMediaFolder "gemini_unified_log_v4.0.0.txt"; Write-Warning "Defaulting `$myLogFile='$myLogFile'." }
if (-not (Get-Variable -Name 'myAuthor' -ErrorAction SilentlyContinue)) { $myAuthor = "PowerShell User" }
if (-not (Get-Variable -Name 'vertexProjectID' -ErrorAction SilentlyContinue)) { $vertexProjectID = ""; Write-Warning "Variable `$vertexProjectID is empty. Set it for Vertex features." }
if (-not (Get-Variable -Name 'vertexLocationId' -ErrorAction SilentlyContinue)) { $vertexLocationId = "us-central1" } # Common default
if (-not (Get-Variable -Name 'vertexDefaultOutputFolder' -ErrorAction SilentlyContinue)) { $vertexDefaultOutputFolder = Join-Path $myMediaFolder "GeneratedImages"; Write-Warning "Defaulting `$vertexDefaultOutputFolder='$vertexDefaultOutputFolder'."; if (-not (Test-Path $vertexDefaultOutputFolder)) { New-Item -Path $vertexDefaultOutputFolder -ItemType Directory -Force > $null } }
if (-not (Get-Variable -Name 'ExifToolPath' -ErrorAction SilentlyContinue)) { $ExifToolPath = ""; Write-Warning "Variable `$ExifToolPath is empty. Ensure exiftool.exe is in PATH or set this variable." }

# Set API Key securely (e.g., $env:GEMINI_API_KEY or prompt)
# Check API Key (prioritize script-level $apiKey var, then environment, then error)
# Note: Start-GeminiChat will prompt if $apiKey is still null when it's called.
if ((Get-Variable -Name 'apiKey' -ErrorAction SilentlyContinue) -and $apiKey) { Write-Verbose "Using \$apiKey from script scope." }
elseif ($env:GEMINI_API_KEY) { $apiKey = $env:GEMINI_API_KEY; Write-Verbose "Using \$apiKey from environment variable GEMINI_API_KEY." }
else { Write-Warning "API Key not found in script scope (`$apiKey`) or environment (`$env:GEMINI_API_KEY`). The function will prompt if called directly." }


# --- Example Execution Options ---
# Uncomment ONE block below. Ensure required variables (like $apiKey) are set.

# Example 1: Process files with modifications
<#
if ($apiKey -and (Test-Path $myMediaFolder)) {
    Write-Host "`n--- Running Example 1: File Processing ---`n" -F Yellow
    # Ensure a dummy file exists for testing
    # if (-not (Get-ChildItem -Path $myMediaFolder -Filter *.jpg -File)) { Set-Content -Path (Join-Path $myMediaFolder "test.jpg") -Value "..." -Force }
    Start-GeminiChat -ApiKey $apiKey -Model 'gemini-1.5-flash' `
        -StartPrompt $examplePrompt -MediaFolder $myMediaFolder -ModifyFiles `
        -UpdateTitle -UpdateAuthor -AuthorName $myAuthor -UpdateSubject -UpdateTags `
        -UpdateRating -UpdateLocation -UpdateDescription `
        -ExifToolPath $ExifToolPath -OutputFile $myLogFile -FileDelaySec 1 -Verbose `
        -ResultsCsvFile (Join-Path $myMediaFolder "parsed_results.csv") `
        -CsvOutputFile (Join-Path $myMediaFolder "chat_history.csv")
} elseif (-not $apiKey) { Write-Error "API Key (`$apiKey`) is not set for Example 1." }
  else { Write-Warning "Media folder '$myMediaFolder' not found for Example 1." }
#>

# Example 2: Interactive chat with Vertex AI configured
#<#
if ($apiKey -and $vertexProjectID -and $vertexLocationId -and $vertexDefaultOutputFolder) {
    Write-Host "`n--- Running Example 2: Interactive Chat + Vertex AI ---`n" -F Yellow
    Start-GeminiChat -ApiKey $apiKey -Model 'gemini-1.5-flash' `
        -VertexProjectId $vertexProjectID -VertexLocationId $vertexLocationId -VertexDefaultOutputFolder $vertexDefaultOutputFolder `
        -VertexImageModel "imagen-3.0-fast-generate-001" -OutputFile $myLogFile -Verbose `
        -CsvOutputFile (Join-Path $myMediaFolder "chat_history_gen.csv")
    # Chat commands: /generate A futuristic cityscape | /imagemodel imagen-3.0-generate-002 | /generate_from ./Review_Photos/test.jpg
} elseif (-not $apiKey) { Write-Error "API Key (`$apiKey`) is not set for Example 2." }
  else { Write-Warning "Vertex AI parameters (`$vertexProjectID`, etc.) missing or incomplete for Example 2." }
#>

# Example 3: Basic interactive chat
# <#
# if ($apiKey) {
#     Write-Host "`n--- Running Example 3: Basic Interactive Chat ---`n" -F Yellow
#     Start-GeminiChat -ApiKey $apiKey -Model 'gemini-1.5-flash' -Verbose
# } else { Write-Error "API Key (`$apiKey`) is not set for Example 3." }
# #>

# --- Final Message ---
if (Get-Command 'Start-GeminiChat' -ErrorAction SilentlyContinue) {
     Write-Host "`nScript loaded. Helper functions defined." -ForegroundColor Green
     Write-Host "Uncomment an example block or call Start-GeminiChat directly." -ForegroundColor Green
     Write-Host "Ensure required variables (like `'$apiKey`') are set or passed via parameters." -ForegroundColor Green
}
```