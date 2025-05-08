# GeminiApiUtils.ps1
# Contains functions for interacting with the Google Gemini API.

#Requires -Version 7

# Depends on CoreUtils.ps1 for Get-MimeTypeFromFile

# --- Helper: Upload File via File API ---
function Upload-GeminiFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$FileInfo,
        [int]$TimeoutSec = 600 # Increase upload timeout to match main API timeout
    )
    # ... (Upload-GeminiFile function body from original script v3.5.11 / modular v4.0.0) ...
    # (Ensure it uses Get-MimeTypeFromFile defined in CoreUtils.ps1)
    Write-Verbose "[Upload-GeminiFile] Uploading '$($FileInfo.Name)' ($(($FileInfo.Length / 1MB).ToString('F2')) MB) via File API..."
    $uploadUrl = "https://generativelanguage.googleapis.com/v1beta/files?key=$ApiKey"
    $mimeType = Get-MimeTypeFromFile -FileInfo $FileInfo # Assumes CoreUtils.ps1 is loaded
    if ([string]::IsNullOrWhiteSpace($mimeType) -or $mimeType -eq 'application/octet-stream') {
        Write-Error "[Upload-GeminiFile] Cannot determine valid MIME type for '$($FileInfo.Name)'. Upload aborted."
        return $null
    }
    $result = @{ Success = $false; FileUri = $null; ErrorRecord = $null }
    $userAgent = "PowerShell-GeminiApi-Client/FileUploader-4.0.0"
    $totalSize = $FileInfo.Length; $startTime = Get-Date; $progressId = Get-Random

    # Progress bar code removed
    $progressJob = $null
    try {
        # Progress job start removed
        Write-Verbose "[Upload-GeminiFile] Progress reporting job removed."
        $headers = @{ "X-Goog-Upload-Protocol" = "raw"; "X-Goog-Upload-File-Name" = $FileInfo.Name; "Content-Type" = $mimeType; "User-Agent" = $userAgent }
        Write-Verbose "[Upload-GeminiFile] Sending upload request to $uploadUrl..."
        $response = Invoke-RestMethod -Uri $uploadUrl -Method Post -Headers $headers -InFile $FileInfo.FullName -TimeoutSec $TimeoutSec -ErrorAction Stop
        if ($response?.file?.uri) { $result.Success = $true; $result.FileUri = $response.file.uri; Write-Verbose "[Upload-GeminiFile] Upload successful. URI: $($result.FileUri)" }
        else { throw "File API response did not contain expected file URI. Response: $($response | ConvertTo-Json -Depth 3 -Compress)" }
    } catch {
        $result.ErrorRecord = $_; Write-Error "[Upload-GeminiFile] Failed to upload file '$($FileInfo.Name)': $($_.Exception.Message)"
        if ($_.Exception.Response) { try { $stream = $_.Exception.Response.GetResponseStream(); $reader = New-Object System.IO.StreamReader($stream); $errorBody = $reader.ReadToEnd(); $reader.Close(); Write-Error "[Upload-GeminiFile] Error Body: $errorBody" } catch { Write-Warning "[Upload-GeminiFile] Could not read error response body." } }
    } finally {
        # Progress bar cleanup removed
    }
    return [PSCustomObject]$result
}


# --- Core Gemini API Interaction Function ---
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
        [string[]]$InlineFilePaths,
        # Compression parameters passed from session config
        [bool]$CompressMedia = $false,
        [string]$FFmpegPath,
        [string]$CompressionPreset = 'medium'
    )
    # ... (Invoke-GeminiApi function body from original script v3.5.11 / modular v4.0.0) ...
    # (Ensure it uses Upload-GeminiFile defined above and Get-MimeTypeFromFile from CoreUtils.ps1)
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
        # Updated to include compression logic
        function Add-MediaPart {
            param(
                [string]$ApiKey,
                [System.IO.FileInfo]$FileInfo,
                [long]$MaxSize,
                [System.Collections.ArrayList]$PartsList,
                [bool]$CompressMedia,
                [string]$FFmpegPath,
                [string]$CompressionPreset
            )

            $originalFileInfo = $FileInfo # Keep original info
            $tempCompressedFilePath = $null
            $isVideo = $false

            $mimeType = Get-MimeTypeFromFile -FileInfo $FileInfo # From CoreUtils
            if ([string]::IsNullOrWhiteSpace($mimeType) -or $mimeType -eq 'application/octet-stream') { Write-Warning "[Invoke-GeminiApi] Invalid MIME type for '$($FileInfo.Name)'. Skipping."; return $false }
            if ($mimeType -like 'video/*') { $isVideo = $true }

            # --- Compression Logic ---
            if ($CompressMedia -and $FFmpegPath -and $isVideo) {
                Write-Verbose "[Invoke-GeminiApi] Attempting video compression for '$($FileInfo.Name)' using preset '$CompressionPreset'..."
                $tempCompressedFileName = "compressed_$($FileInfo.BaseName)_$(Get-Random).mp4" # Use mp4 for output
                $tempCompressedFilePath = Join-Path -Path $env:TEMP -ChildPath $tempCompressedFileName
                # Example FFmpeg args - adjust as needed for balance of quality/size/speed
                # -vf scale=-2:720 scales height to 720p, keeping aspect ratio
                # -crf 28 is a reasonable quality setting (lower is better quality, larger file)
                # -preset controls encoding speed vs compression efficiency
                $ffmpegArgs = "-i `"$($FileInfo.FullName)`" -vf scale=-2:720 -c:v libx264 -crf 28 -preset $CompressionPreset -c:a aac -b:a 128k -movflags +faststart -y `"$tempCompressedFilePath`""
                Write-Verbose "  FFmpeg command: ffmpeg.exe $ffmpegArgs"
                try {
                    $process = Start-Process -FilePath $FFmpegPath -ArgumentList $ffmpegArgs -Wait -NoNewWindow -PassThru -ErrorAction Stop
                    if ($process.ExitCode -ne 0) { throw "FFmpeg failed with exit code $($process.ExitCode)." }
                    $compressedFileInfo = Get-Item -LiteralPath $tempCompressedFilePath -ErrorAction Stop
                    Write-Verbose "  Compression successful. Original size: $(($originalFileInfo.Length / 1MB).ToString('F2')) MB, Compressed size: $(($compressedFileInfo.Length / 1MB).ToString('F2')) MB."
                    $FileInfo = $compressedFileInfo # Use the compressed file for subsequent steps
                    # Mime type remains video/mp4 as we output mp4
                    $mimeType = 'video/mp4'
                } catch {
                    Write-Warning "[Invoke-GeminiApi] FFmpeg compression failed for '$($originalFileInfo.Name)': $($_.Exception.Message). Using original file."
                    if (Test-Path -LiteralPath $tempCompressedFilePath) { Remove-Item -LiteralPath $tempCompressedFilePath -Force -EA SilentlyContinue }
                    $tempCompressedFilePath = $null # Ensure it's null if compression failed
                    $FileInfo = $originalFileInfo # Revert to original FileInfo
                }
            }
            # --- End Compression Logic ---

            if ($FileInfo.Length -lt $MaxSize) { Write-Verbose "[Invoke-GeminiApi] Encoding inline: '$($FileInfo.Name)'..."; $bytes = [System.IO.File]::ReadAllBytes($FileInfo.FullName); $b64 = [System.Convert]::ToBase64String($bytes); [void]$PartsList.Add(@{ inline_data = @{ mime_type = $mimeType; data = $b64 } }) }
            else { Write-Verbose "[Invoke-GeminiApi] Uploading large file: '$($FileInfo.Name)'..."; $uploadResult = Upload-GeminiFile -ApiKey $ApiKey -FileInfo $FileInfo; if ($uploadResult?.Success) { [void]$PartsList.Add(@{ file_data = @{ mime_type = $mimeType; file_uri = $uploadResult.FileUri } }) } else { throw "Failed to upload large file '$($FileInfo.Name)'. Error: $($uploadResult.ErrorRecord.Exception.Message)" } }

            # --- Cleanup Temporary Compressed File ---
            if ($tempCompressedFilePath -and (Test-Path -LiteralPath $tempCompressedFilePath)) {
                Write-Verbose "  Cleaning up temporary compressed file: $tempCompressedFilePath"
                Remove-Item -LiteralPath $tempCompressedFilePath -Force -ErrorAction SilentlyContinue
            }
            # --- End Cleanup ---

            return $true
        }
        # --- End Internal Helper ---

        try {
            $allMediaFiles = [System.Collections.ArrayList]::new()
            if ($PSBoundParameters.ContainsKey('InlineFilePaths') -and $InlineFilePaths) {
                Write-Verbose "[Invoke-GeminiApi] Processing $($InlineFilePaths.Count) file(s) from -InlineFilePaths."
                foreach ($filePath in $InlineFilePaths) {
                    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) { Write-Warning "[Invoke-GeminiApi] File not found: '$filePath'. Skipping."; continue }
                    [void]$allMediaFiles.Add((Get-Item -LiteralPath $filePath -EA Stop))
                }
            }
            elseif ($PSBoundParameters.ContainsKey('ImageFolder') -or $PSBoundParameters.ContainsKey('VideoFolder')) {
                 Write-Verbose "[Invoke-GeminiApi] Processing media from -ImageFolder/-VideoFolder..."
                 # Use Get-StartMediaFiles (defined outside)
                 $imgExt = @('.jpg', '.jpeg', '.png', '.webp', '.gif', '.heic', '.heif', '.bmp', '.tif', '.tiff')
                 $vidExt = @('.mp4', '.mpeg', '.mov', '.avi', '.flv', '.mpg', '.webm', '.wmv', '.3gp', '.3gpp', '.mkv')
                 if ($PSBoundParameters.ContainsKey('ImageFolder')) { $imgFiles = Get-StartMediaFiles -FolderPath $ImageFolder -Recurse:$Recurse.IsPresent -SupportedExtensions $imgExt -MediaType 'image'; if ($imgFiles) { $imgFiles | ForEach-Object { [void]$allMediaFiles.Add($_) } } }
                 if ($PSBoundParameters.ContainsKey('VideoFolder') -and $VideoFolder -ne $ImageFolder) { $vidFiles = Get-StartMediaFiles -FolderPath $VideoFolder -Recurse:$Recurse.IsPresent -SupportedExtensions $vidExt -MediaType 'video'; if ($vidFiles) { $vidFiles | ForEach-Object { [void]$allMediaFiles.Add($_) } } }
                 Write-Verbose "[Invoke-GeminiApi] Found $($allMediaFiles.Count) media file(s) in folders."
            }
            else { Write-Verbose "[Invoke-GeminiApi] No media files provided for this call." }

            foreach ($fileInfo in $allMediaFiles) {
                $addSuccess = Add-MediaPart `
                    -ApiKey $ApiKey `
                    -FileInfo $fileInfo `
                    -MaxSize $maxInlineDataSizeBytes `
                    -PartsList $currentUserParts `
                    -CompressMedia $CompressMedia `
                    -FFmpegPath $FFmpegPath `
                    -CompressionPreset $CompressionPreset
                if (-not $addSuccess) { /* Optional: Handle specific skipping */ }
            }
        } catch { Write-Error "[Invoke-GeminiApi] Failed processing media: $($_.Exception.Message)"; $result.ErrorRecord = $_; $result.Success = $false; return $result }

        $currentHistoryPayload = [System.Collections.ArrayList]::new($ConversationHistory) # Copy history
        $currentUserTurn = @{ role = 'user'; parts = $currentUserParts.ToArray() }; [void]$currentHistoryPayload.Add($currentUserTurn)
        $requestPayload = @{ contents = $currentHistoryPayload.ToArray() }; if ($GenerationConfig) { $requestPayload.Add('generationConfig', $GenerationConfig) }

        $currentRetry = 0; $response = $null; $userAgent = "PowerShell-GeminiApi-Client/Unified-4.0.0"
        while ($currentRetry -le $MaxRetries) {
            try {
                $requestBodyJson = $requestPayload | ConvertTo-Json -Depth 15; Write-Verbose "[Invoke-GeminiApi] Request $($currentRetry+1)... Preview: $($requestBodyJson.Substring(0,[System.Math]::Min($requestBodyJson.Length,300)))..."
                $headers = @{ "Content-Type" = "application/json"; "User-Agent" = $userAgent }
                $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $requestBodyJson -ContentType "application/json" -TimeoutSec $TimeoutSec -ErrorAction Stop
                Write-Verbose "[Invoke-GeminiApi] Request successful."; break
            }
            catch [System.Net.WebException] {
                $webEx = $_
                $statusCode = if ($webEx.Exception.Response) { [int]$webEx.Exception.Response.StatusCode } else { $null }
                $result.ErrorRecord = $webEx
                $result.StatusCode = $statusCode
                $specificLocationError = $false

                try {
                    if ($webEx.Exception.Response) {
                        $stream = $webEx.Exception.Response.GetResponseStream()
                        $reader = New-Object System.IO.StreamReader($stream)
                        $result.ResponseBody = $reader.ReadToEnd()
                        $reader.Close()
                        Write-Verbose "[Invoke-GeminiApi] Error Body: $($result.ResponseBody)" # Log full error body if verbose

                        if ($statusCode -eq 400) {
                            try {
                                $errorObject = $result.ResponseBody | ConvertFrom-Json -ErrorAction SilentlyContinue
                                if ($errorObject.error.message -match "User location is not supported") {
                                    $specificLocationError = $true
                                }
                            } catch { Write-Verbose "[Invoke-GeminiApi] Could not parse 400 error body as JSON or find specific location message." }
                        }
                    }
                } catch { Write-Warning "[Invoke-GeminiApi] Could not fully process error response body: $($_.Exception.Message)" }

                $errorMsg = "[Invoke-GeminiApi] Web exception (Status: $statusCode)." # Default message
                if ($specificLocationError) {
                    $errorMsg = "[Invoke-GeminiApi] API Error (400 - FAILED_PRECONDITION): User location is not supported for API use. Please check your Google Cloud project settings, API key restrictions, and Gemini API regional availability. Full error body logged if -Verbose is used."
                } elseif ($statusCode -eq 400) {
                    $errorMsg = "[Invoke-GeminiApi] API Error (400 - Bad Request). Check request details. Full error body logged if -Verbose is used."
                }

                if ($statusCode -eq 429 -and $currentRetry -lt $MaxRetries) {
                    $currentRetry++; $delay = ($InitialRetryDelaySec * ([Math]::Pow(2, $currentRetry - 1))) + (Get-Random -Minimum 0 -Maximum 1000) / 1000.0
                    Write-Warning "[Invoke-GeminiApi] Rate limit (429). Retrying $currentRetry/$($MaxRetries + 1) in $($delay.ToString('F2'))s..."
                    Start-Sleep -Seconds $delay; continue
                } else { Write-Error $errorMsg; break }
            }
            catch { $errMsg = "[Invoke-GeminiApi] Error: $($_.Exception.Message)"; Write-Error $errMsg; $result.ErrorRecord = $_; $result.ResponseBody = $errMsg; break }
        }

        if ($response) {
            if ($response.candidates[0]?.content?.parts[0]?.text) { $result.GeneratedText = $response.candidates[0].content.parts[0].text; $result.Success = $true; $result.StatusCode = 200; Write-Verbose "[Invoke-GeminiApi] Response parsed."; $modelResponseTurn = $response.candidates[0].content; [void]$currentHistoryPayload.Add($modelResponseTurn); $result.UpdatedConversationHistory = $currentHistoryPayload.ToArray() }
            elseif ($response.promptFeedback?.blockReason) { $reason=$response.promptFeedback.blockReason;$ratings=$response.promptFeedback.safetyRatings|ConvertTo-Json -Depth 3 -Comp;$errMsg="[Invoke-GeminiApi] Blocked. Reason: $reason. Ratings: $ratings";Write-Error $errMsg;$result.ResponseBody=$response|ConvertTo-Json -Depth 10;$result.ErrorRecord=New-Object System.Management.Automation.ErrorRecord([System.Exception]::new($errMsg),"SafetyBlock",[System.Management.Automation.ErrorCategory]::PermissionDenied,$response);$result.StatusCode=200 }
            else { Write-Warning "[Invoke-GeminiApi] Unexpected response structure."; $result.ResponseBody=$response|ConvertTo-Json -Depth 10;$result.StatusCode=200;$result.ErrorRecord=New-Object System.Management.Automation.ErrorRecord([System.Exception]::new("Unexpected API response."),"UnexpectedApiResponse",[System.Management.Automation.ErrorCategory]::InvalidData,$response) }
        } elseif (-not $result.ErrorRecord) { Write-Error "[Invoke-GeminiApi] API call failed after retries."; $result.ErrorRecord = New-Object System.Management.Automation.ErrorRecord([System.Exception]::new("API retries failed."),"ApiRetryFailure",[System.Management.Automation.ErrorCategory]::OperationTimeout,$null) }

        Write-Verbose "[Invoke-GeminiApi] Function finished."
        return $result
    }
    End { }
}

Write-Verbose "GeminiApiUtils.ps1 loaded."
