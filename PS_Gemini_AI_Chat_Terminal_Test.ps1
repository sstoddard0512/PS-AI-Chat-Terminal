# Unified Script: Start-GeminiChat - v3.5.5
# Combines features from SimpleMods (v1.23) and Batch (v2.78)
# - Processes initial media folder files one-by-one (-MediaFolder, -StartPrompt)
# - Supports metadata modification (-ModifyFiles, -Update*, -Confirm)
# - Supports GPS reading, location prompting, filename update, and metadata update via -UpdateLocation
# - Supports interactive media upload (folder or file) in subsequent turns via /media command
# - Includes rate limit delay (-FileDelaySec)
# - Requires ExifTool for modifications or location processing.
# - Removed unreliable -SkipProcessedFiles feature.
# - Added interactive commands: /history, /clear, /retry, /config, /save, /media, /generate, /generate_from, /model
# - Added CSV export functionality (-CsvOutputFile, /save)
# - Added parsed results CSV export (-ResultsCsvFile)
# - Modified /media command to prompt for text immediately after media selection and accept path argument.
# - Added support for large file uploads (>20MB) via Google AI File API.

# --- Helper Function: Get MIME Type ---
function Get-MimeTypeFromFile {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$FileInfo
    )
    $extension = $FileInfo.Extension.ToLowerInvariant()
    # Comprehensive MIME type list
    $mimeType = switch ($extension) {
        # Images
        '.jpg'  { 'image/jpeg' }; '.jpeg' { 'image/jpeg' }; '.png'  { 'image/png' }; '.webp' { 'image/webp' }; '.gif'  { 'image/gif' }; '.heic' { 'image/heic'}; '.heif' { 'image/heif'}; '.bmp' { 'image/bmp'}; '.tif' { 'image/tiff'}; '.tiff' { 'image/tiff'}
        # Videos
        '.mp4'  { 'video/mp4' }; '.mpeg' { 'video/mpeg' }; '.mpg'  { 'video/mpeg' }; '.mov'  { 'video/quicktime' }; '.avi'  { 'video/x-msvideo' }; '.flv'  { 'video/x-flv'}; '.webm' { 'video/webm' }; '.wmv'  { 'video/x-ms-wmv'}; '.3gp'  { 'video/3gpp'}; '.3gpp' { 'video/3gpp'}; '.mkv' { 'video/x-matroska'}
        # Audio
        '.mp3'  { 'audio/mpeg' }; '.wav'  { 'audio/wav' }; '.ogg'  { 'audio/ogg' }; '.flac' { 'audio/flac' }; '.m4a'  { 'audio/mp4' }; '.aac' { 'audio/aac'}; '.wma' { 'audio/x-ms-wma'}
        # Documents
        '.txt'  { 'text/plain' }; '.pdf'  { 'application/pdf' }; '.htm'  { 'text/html' }; '.html' { 'text/html' }; '.json' { 'application/json' }; '.csv'  { 'text/csv' }; '.xml' { 'application/xml'}; '.rtf' { 'application/rtf'}; '.md' { 'text/markdown'}
        # Default
        default { Write-Warning "[Get-MimeTypeFromFile] Cannot determine MIME type for '$($FileInfo.Name)' (Extension: '$extension'). Using 'application/octet-stream'."; 'application/octet-stream' }
    }
    return $mimeType
}

# --- Helper function to sanitize text for filenames ---
function Sanitize-Filename {
    param([string]$InputString, [int]$MaxLength = 100)
    if ([string]::IsNullOrWhiteSpace($InputString)) { return "gemini_response_$(Get-Random)" }
    # Remove invalid filename characters, replace common separators with underscore
    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars() -join ''; $charsToReplace = $invalidChars + ",'"; $regexInvalid = "[{0}]" -f ([RegEx]::Escape($charsToReplace))
    $sanitized = $InputString -replace $regexInvalid, '_' -replace '\s+', '_' -replace '_+', '_'
    # Truncate if too long
    if ($sanitized.Length -gt $MaxLength) { $sanitized = $sanitized.Substring(0, $MaxLength) }
    # Remove leading/trailing underscores
    $sanitized = $sanitized.Trim('_')
    # Ensure result is not empty
    if ([string]::IsNullOrWhiteSpace($sanitized)) { $sanitized = "gemini_response_$(Get-Random)" }; return $sanitized
}

# --- NEW HELPER: Upload File via File API ---
function Upload-GeminiFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$FileInfo,
        [int]$TimeoutSec = 180 # Separate timeout for upload
    )
    Write-Verbose "[Upload-GeminiFile] Uploading '$($FileInfo.Name)' ($(($FileInfo.Length / 1MB).ToString('F2')) MB) via File API..."
    $uploadUrl = "https://generativelanguage.googleapis.com/v1beta/files?key=$ApiKey"
    $mimeType = Get-MimeTypeFromFile -FileInfo $FileInfo
    if ([string]::IsNullOrWhiteSpace($mimeType) -or $mimeType -eq 'application/octet-stream') {
        Write-Error "[Upload-GeminiFile] Cannot determine valid MIME type for '$($FileInfo.Name)'. Upload aborted."
        return $null
    }

    $result = @{ Success = $false; FileUri = $null; ErrorRecord = $null }
    $userAgent = "PowerShell-GeminiApi-Client/FileUploader-3.5.5" # Updated version

    try {
        # Use Invoke-RestMethod with -InFile for efficient large file upload
        $headers = @{
            "X-Goog-Upload-Protocol" = "raw" # Simple raw upload
            "X-Goog-Upload-File-Name" = $FileInfo.Name
            "Content-Type" = $mimeType
            "User-Agent" = $userAgent
        }

        Write-Verbose "[Upload-GeminiFile] Sending upload request to $uploadUrl..."
        # Note: Invoke-RestMethod might still have limitations depending on PS version/memory.
        # Consider alternative methods (like .NET HttpClient) for very large files if this fails.
        $response = Invoke-RestMethod -Uri $uploadUrl -Method Post -Headers $headers -InFile $FileInfo.FullName -TimeoutSec $TimeoutSec -ErrorAction Stop

        if ($response -and $response.file -and $response.file.uri) {
            $result.Success = $true
            $result.FileUri = $response.file.uri
            Write-Verbose "[Upload-GeminiFile] Upload successful. File URI: $($result.FileUri)"
        } else {
            throw "File API response did not contain expected file URI. Response: $($response | ConvertTo-Json -Depth 3 -Compress)"
        }
    } catch {
        $result.ErrorRecord = $_
        Write-Error "[Upload-GeminiFile] Failed to upload file '$($FileInfo.Name)': $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $errorBody = $reader.ReadToEnd()
                Write-Error "[Upload-GeminiFile] Error Body: $errorBody"
            } catch { Write-Warning "[Upload-GeminiFile] Could not read error response body." }
        }
    }
    return [PSCustomObject]$result
}

# --- Nested Core API Interaction Function ---
function Invoke-GeminiApi {
    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory = $true)] [string]$ApiKey,
        [Parameter(Mandatory = $true)] [string]$Prompt,
        [array]$ConversationHistory,
        [string]$Model = 'gemini-1.5-pro-latest',
        [string]$ImageFolder, # For interactive folder upload
        [string]$VideoFolder, # For interactive folder upload
        [switch]$Recurse,     # For interactive folder upload
        [hashtable]$GenerationConfig,
        [int]$TimeoutSec = 300,
        [ValidateRange(0, 5)] [int]$MaxRetries = 3,
        [ValidateRange(1, 60)] [int]$InitialRetryDelaySec = 2,
        [string[]]$InlineFilePaths # For first-turn single file OR interactive single file
    )
    Begin { # Added Begin block for clarity
        Write-Verbose "[Invoke-GeminiApi] Starting function (Unified v3.5.5)."
        $apiUrlTemplate = "https://generativelanguage.googleapis.com/v1beta/models/{0}:generateContent?key={1}"
        $apiUrl = $apiUrlTemplate -f $Model, $ApiKey
        Write-Verbose "[Invoke-GeminiApi] Using generateContent API URL: $apiUrl"
        $supportedImageExtensions = '.jpg', '.jpeg', '.png', '.webp', '.gif', '.heic', '.heif', '.bmp', '.tif', '.tiff'
        $supportedVideoExtensions = '.mp4', '.mpeg', '.mov', '.avi', '.flv', '.mpg', '.webm', '.wmv', '.3gp', '.3gpp', '.mkv'

        # Define a size threshold (e.g., 20MB) for using inline data vs. File API
        $maxInlineDataSizeBytes = 20 * 1024 * 1024
    }
    Process {
        $result = [PSCustomObject]@{
            Success                = $false; GeneratedText          = $null; ModelUsed              = $Model
            UpdatedConversationHistory = $null; DiscoveredImagePaths   = $null; DiscoveredVideoPaths   = $null
            ErrorRecord            = $null; StatusCode             = $null; ResponseBody           = $null
        }
        $currentUserParts = [System.Collections.ArrayList]::new(); [void]$currentUserParts.Add(@{ text = $Prompt })

        # Internal helper to find media files within this function's scope
        function Get-MediaFilesInternal {
            param([string]$FolderPath, [switch]$Recurse, [string[]]$SupportedExtensions, [string]$MediaType)
            Write-Verbose "[Invoke-GeminiApi] Searching for $MediaType files in folder: $FolderPath $($Recurse ? ' (Recursively)' : '')"
            $discoveredFiles = @(); try { $gciParams = @{ Path = $FolderPath; File = $true; ErrorAction = 'Stop' }; if ($Recurse) { $gciParams.Recurse = $true }; $discoveredFiles = Get-ChildItem @gciParams | Where-Object { $SupportedExtensions -contains $_.Extension.ToLowerInvariant() }; if ($discoveredFiles.Count -eq 0) { Write-Warning "No supported $MediaType files ($($SupportedExtensions -join ', ')) found in '$FolderPath'$($Recurse ? ' or its subdirectories' : '')." } else { Write-Verbose "[Invoke-GeminiApi] Found $($discoveredFiles.Count) supported $MediaType file(s)." }; return $discoveredFiles } catch { Write-Error "Failed to access or search $MediaType folder '$FolderPath': $($_.Exception.Message)"; return $null }
        }

        $discoveredImageFiles = @(); $discoveredVideoFiles = @()

        # Priority 1: Specific Inline File Paths provided directly
        if ($PSBoundParameters.ContainsKey('InlineFilePaths') -and $null -ne $InlineFilePaths -and $InlineFilePaths.Count -gt 0) {
            Write-Verbose "[Invoke-GeminiApi] Adding $($InlineFilePaths.Count) file(s) from provided paths."
            foreach ($filePath in $InlineFilePaths) {
                if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) { Write-Warning "[Invoke-GeminiApi] File not found: '$filePath'. Skipping."; continue }
                try {
                    $fileInfo = Get-Item -LiteralPath $filePath -EA Stop; $mimeType = Get-MimeTypeFromFile -FileInfo $fileInfo
                    if ([string]::IsNullOrWhiteSpace($mimeType) -or $mimeType -eq 'application/octet-stream') { Write-Warning "[Invoke-GeminiApi] Could not determine valid MIME type for '$($fileInfo.Name)'. Skipping file."; continue }

                    # Check file size against threshold
                    if ($fileInfo.Length -lt $maxInlineDataSizeBytes) {
                        Write-Verbose "[Invoke-GeminiApi] Encoding inline: '$($fileInfo.Name)' ($(($fileInfo.Length / 1MB).ToString('F2')) MB)..."; $fileBytes = [System.IO.File]::ReadAllBytes($filePath); $base64Data = [System.Convert]::ToBase64String($fileBytes)
                        [void]$currentUserParts.Add(@{ inline_data = @{ mime_type = $mimeType; data = $base64Data } })
                    } else {
                        Write-Verbose "[Invoke-GeminiApi] File '$($fileInfo.Name)' ($(($fileInfo.Length / 1MB).ToString('F2')) MB) exceeds inline threshold. Using File API..."
                        $uploadResult = Upload-GeminiFile -ApiKey $ApiKey -FileInfo $fileInfo # TimeoutSec could be added here
                        if ($uploadResult -and $uploadResult.Success) {
                            [void]$currentUserParts.Add(@{ file_data = @{ mime_type = $mimeType; file_uri = $uploadResult.FileUri } })
                        } else {
                            throw "Failed to upload file '$($fileInfo.Name)' via File API. Error: $($uploadResult.ErrorRecord.Exception.Message)" # Throw to be caught below
                        }
                    }
                } catch { Write-Error "[Invoke-GeminiApi] Failed processing file '$filePath': $($_.Exception.Message)"; $result.ErrorRecord = New-Object System.Management.Automation.ErrorRecord -ArgumentList @([System.Exception]::new("Failed processing file '$filePath': $($_.Exception.Message)", $_.Exception), "FileProcessingError", [System.Management.Automation.ErrorCategory]::ReadError, $filePath); $result.Success = $false; return $result }
            }
        }
        # Priority 2: Folder-based media for interactive turns
        elseif ($PSBoundParameters.ContainsKey('ImageFolder') -or $PSBoundParameters.ContainsKey('VideoFolder')) {
            Write-Verbose "[Invoke-GeminiApi] Processing media from specified folders..."
            if ($PSBoundParameters.ContainsKey('ImageFolder')) {
                $imgFiles = Get-MediaFilesInternal -FolderPath $ImageFolder -Recurse:$Recurse.IsPresent -SupportedExtensions $supportedImageExtensions -MediaType 'image'
                if ($null -eq $imgFiles) {
                    # Error occurred accessing/searching the folder
                    $errMsg = "[Invoke-GeminiApi] Failed to access or search Image folder '$ImageFolder'. Skipping images from this source."
                    Write-Error $errMsg
                    # Store the error, but don't return immediately
                    $result.ErrorRecord = New-Object System.Management.Automation.ErrorRecord -ArgumentList @([System.IO.DirectoryNotFoundException]::new($errMsg), "FolderAccessOrSearchError", [System.Management.Automation.ErrorCategory]::ReadError, $ImageFolder )
                }
                if ($imgFiles.Count -gt 0) { $discoveredImageFiles = $imgFiles; $result.DiscoveredImagePaths = $discoveredImageFiles.FullName }
            }
            if ($PSBoundParameters.ContainsKey('VideoFolder')) {
                $vidFiles = Get-MediaFilesInternal -FolderPath $VideoFolder -Recurse:$Recurse.IsPresent -SupportedExtensions $supportedVideoExtensions -MediaType 'video'
                if ($null -eq $vidFiles) {
                    # Error occurred accessing/searching the folder
                    $errMsg = "[Invoke-GeminiApi] Failed to access or search Video folder '$VideoFolder'. Skipping videos from this source."
                    Write-Error $errMsg
                    # Store the error, but don't return immediately
                    $result.ErrorRecord = New-Object System.Management.Automation.ErrorRecord -ArgumentList @([System.IO.DirectoryNotFoundException]::new($errMsg), "FolderAccessOrSearchError", [System.Management.Automation.ErrorCategory]::ReadError, $VideoFolder )
                }
                if ($vidFiles.Count -gt 0) { $discoveredVideoFiles = $vidFiles; $result.DiscoveredVideoPaths = $discoveredVideoFiles.FullName }
            }

            # Process discovered files from folders
            $allMediaFiles = @($discoveredImageFiles) + @($discoveredVideoFiles)
            if ($allMediaFiles.Count -gt 0) {
                 Write-Verbose "[Invoke-GeminiApi] Processing $($allMediaFiles.Count) media file(s) from folders..."
                 foreach ($mediaFile in $allMediaFiles) {
                    $singleMediaPath = $mediaFile.FullName
                    try {
                        $fileInfo = $mediaFile # Use the FileInfo object directly
                        $mimeType = Get-MimeTypeFromFile -FileInfo $fileInfo
                        if ([string]::IsNullOrWhiteSpace($mimeType) -or $mimeType -eq 'application/octet-stream') { Write-Warning "[Invoke-GeminiApi] Could not determine valid MIME type for '$($fileInfo.Name)'. Skipping file."; continue }

                        # Check file size against threshold
                        if ($fileInfo.Length -lt $maxInlineDataSizeBytes) {
                            Write-Verbose "[Invoke-GeminiApi] Encoding inline: '$($fileInfo.Name)' ($(($fileInfo.Length / 1MB).ToString('F2')) MB)..."; $fileBytes = [System.IO.File]::ReadAllBytes($fileInfo.FullName); $base64Data = [System.Convert]::ToBase64String($fileBytes)
                            [void]$currentUserParts.Add(@{ inline_data = @{ mime_type = $mimeType; data = $base64Data } })
                        } else {
                            Write-Verbose "[Invoke-GeminiApi] File '$($fileInfo.Name)' ($(($fileInfo.Length / 1MB).ToString('F2')) MB) exceeds inline threshold. Using File API..."
                            $uploadResult = Upload-GeminiFile -ApiKey $ApiKey -FileInfo $fileInfo # TimeoutSec could be added here
                            if ($uploadResult -and $uploadResult.Success) {
                                [void]$currentUserParts.Add(@{ file_data = @{ mime_type = $mimeType; file_uri = $uploadResult.FileUri } })
                            } else {
                                throw "Failed to upload file '$($fileInfo.Name)' via File API. Error: $($uploadResult.ErrorRecord.Exception.Message)" # Throw to be caught below
                            }
                        }
                    } catch {
                        Write-Error "Failed to process media file '$singleMediaPath': $($_.Exception.Message)"
                        $result.ErrorRecord = New-Object System.Management.Automation.ErrorRecord -ArgumentList @([System.Exception]::new("Failed to process media file '$singleMediaPath': $($_.Exception.Message)", $_.Exception), "MediaProcessingError", [System.Management.Automation.ErrorCategory]::ReadError, $singleMediaPath )
                        return $result # Stop processing if one file fails
                    }
                }
            } else { Write-Verbose "[Invoke-GeminiApi] No supported media files found in specified folders."}

        } else { Write-Verbose "[Invoke-GeminiApi] No media files provided for this call." }

        # Build conversation history payload
        $currentHistoryPayload = [System.Collections.ArrayList]::new()
        if ($PSBoundParameters.ContainsKey('ConversationHistory') -and $null -ne $ConversationHistory -and $ConversationHistory.Count -gt 0) { $ConversationHistory | ForEach-Object { [void]$currentHistoryPayload.Add($_) }; Write-Verbose "[Invoke-GeminiApi] Using history ($($ConversationHistory.Count) turns)." } else { Write-Verbose "[Invoke-GeminiApi] Starting new conversation or processing initial file." }
        $currentUserTurn = @{ role = 'user'; parts = @($currentUserParts) }; [void]$currentHistoryPayload.Add($currentUserTurn)
        $requestPayload = @{ contents = @($currentHistoryPayload) }; if ($PSBoundParameters.ContainsKey('GenerationConfig')) { $requestPayload.Add('generationConfig', $GenerationConfig); Write-Verbose "[Invoke-GeminiApi] Added GenerationConfig." }

        # API Call with Retry Logic
        $currentRetry = 0; $response = $null; $userAgent = "PowerShell-GeminiApi-Client/Unified-3.5.5" # Updated version
        while ($currentRetry -le $MaxRetries) { # Start of retry loop
            try {
                $requestBodyJson = $requestPayload | ConvertTo-Json -Depth 15
                Write-Verbose "[Invoke-GeminiApi] Sending request (Attempt $($currentRetry + 1))... JSON Preview: $($requestBodyJson.Substring(0, [System.Math]::Min($requestBodyJson.Length, 500)))..."
                $headers = @{ "Content-Type" = "application/json"; "User-Agent" = $userAgent }
                $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $requestBodyJson -ContentType "application/json" -TimeoutSec $TimeoutSec -ErrorAction Stop
                Write-Verbose "[Invoke-GeminiApi] Request successful (Status: $($response.PSObject.Properties['StatusCode'].Value))." # Access status code if available
                break # Exit loop on success
            }
            catch [System.Net.WebException] {
                $webEx = $_
                $statusCode = if ($webEx.Exception.Response -ne $null) { [int]$webEx.Exception.Response.StatusCode } else { $null }
                $result.ErrorRecord = $webEx
                $result.StatusCode = $statusCode
                try {
                    if ($webEx.Exception.Response -ne $null) {
                        $stream = $webEx.Exception.Response.GetResponseStream()
                        $reader = New-Object System.IO.StreamReader($stream)
                        $result.ResponseBody = $reader.ReadToEnd() # Capture error body
                        $reader.Close()
                        # --- Always output error body for 400 ---
                        if ($statusCode -eq 400) {
                            Write-Error "[Invoke-GeminiApi] 400 Bad Request Body: $($result.ResponseBody)"
                        }
                        Write-Verbose "[Invoke-GeminiApi] Error Body: $($result.ResponseBody)"
                    }
                } catch { Write-Warning "Could not read error response body." }

                # --- Enhanced Error Message for 400 ---
                $errorMsg = "[Invoke-GeminiApi] Web exception during API call (Status: $statusCode)."
                if ($statusCode -eq 400) {
                    $errorMsg += " This might be due to an invalid API key, malformed request (check prompt, generation config, file data/type/size), an unsupported model/region, or content policy violations. Check the Error Body if available."
                }
                # --- End Enhanced Error Message ---

                if ($statusCode -eq 429 -and $currentRetry -lt $MaxRetries) {
                    $currentRetry++
                    $delay = ($InitialRetryDelaySec * ([Math]::Pow(2, $currentRetry - 1))) + (Get-Random -Minimum 0 -Maximum 1000) / 1000.0
                    Write-Warning "[Invoke-GeminiApi] HTTP 429 Too Many Requests. Retrying attempt $currentRetry/$($MaxRetries + 1) in $($delay.ToString('F2'))s..."
                    Start-Sleep -Seconds $delay
                    continue # Retry
                } else {
                    Write-Error $errorMsg
                    break # Exit the while loop for non-retryable web exceptions
                }
            }
            catch {
                # Catch other non-WebException errors
                $errMsg = "[Invoke-GeminiApi] Unexpected error during API call: $($_.Exception.Message)"
                Write-Error $errMsg
                $result.ErrorRecord = $_
                $result.ResponseBody = $errMsg # Store basic error message if no HTTP response
                break # Exit loop on unexpected error
            }
        } # End while

        # Process the final response (or lack thereof)
        if ($response -ne $null) {
            # Check if the expected candidate structure exists
            if ($response.candidates -ne $null -and $response.candidates -is [array] -and $response.candidates.Count -gt 0 -and $response.candidates[0].content -ne $null -and $response.candidates[0].content.parts -ne $null -and $response.candidates[0].content.parts[0].text) { # More robust check
                $result.GeneratedText = $response.candidates[0].content.parts[0].text
                $result.Success = $true
                $result.StatusCode = 200 # Assuming 200 OK if we got here with valid content
                Write-Verbose "[Invoke-GeminiApi] Parsed response successfully."
                $modelResponseTurn = $response.candidates[0].content
                [void]$currentHistoryPayload.Add($modelResponseTurn)
                $result.UpdatedConversationHistory = @($currentHistoryPayload)
            }
            elseif ($response.promptFeedback.blockReason) {
                $blockReason = $response.promptFeedback.blockReason
                $safetyRatings = $response.promptFeedback.safetyRatings | ConvertTo-Json -Depth 3 -Compress
                $errMsg = "[Invoke-GeminiApi] Request blocked due to safety settings. Reason: $blockReason. Ratings: $safetyRatings"
                Write-Error $errMsg
                $result.ResponseBody = $response | ConvertTo-Json -Depth 10
                $result.ErrorRecord = New-Object System.Management.Automation.ErrorRecord -ArgumentList @([System.Exception]::new($errMsg), "SafetyBlock", [System.Management.Automation.ErrorCategory]::PermissionDenied, $response)
                $result.StatusCode = 200 # API call itself succeeded, but content was blocked
            }
            else {
                # Handle cases where response exists but doesn't have expected content (e.g., empty candidates)
                Write-Warning "[Invoke-GeminiApi] API response received but did not contain expected candidate text or block reason."
                $result.ResponseBody = $response | ConvertTo-Json -Depth 10
                $result.StatusCode = 200 # API call likely succeeded, but response format is unexpected/empty
                $result.ErrorRecord = New-Object System.Management.Automation.ErrorRecord -ArgumentList @( [System.Exception]::new("Unexpected or empty API response structure."), "UnexpectedApiResponseStructure", [System.Management.Automation.ErrorCategory]::InvalidData, $response )
            }
        } elseif ($result.ErrorRecord -eq $null) {
            # This case happens if all retries failed without a specific WebException being caught in the final attempt
            Write-Error "[Invoke-GeminiApi] API call failed after retries, no specific error captured."
            $result.ErrorRecord = New-Object System.Management.Automation.ErrorRecord -ArgumentList @([System.Exception]::new("API call failed after retries."), "ApiRetryFailure", [System.Management.Automation.ErrorCategory]::OperationTimeout, $null)
        }

        Write-Verbose "[Invoke-GeminiApi] Function finished."
        return $result
    }
    End { }
}

# --- Helper function to get media files ---
function Get-StartMediaFiles {
    param([string]$FolderPath, [switch]$Recurse, [string[]]$SupportedExtensions, [string]$MediaType)
    Write-Verbose "[Get-StartMediaFiles] Searching for $MediaType files in: $FolderPath $($Recurse.IsPresent ? '(Recursive)' : '')"
    try { $gciParams = @{ Path = $FolderPath; File = $true; ErrorAction = 'Stop' }; if ($Recurse.IsPresent) { $gciParams.Recurse = $true }; $discoveredFiles = Get-ChildItem @gciParams | Where-Object { $SupportedExtensions -contains $_.Extension.ToLowerInvariant() }; Write-Verbose "[Get-StartMediaFiles] Found $($discoveredFiles.Count) $MediaType file(s)."; return $discoveredFiles }
    catch { Write-Error "[Get-StartMediaFiles] Failed to access/search folder '$FolderPath': $($_.Exception.Message)"; return $null }
}

# --- Main Chat Function ---
<#
.SYNOPSIS
Starts an interactive chat session with Google Gemini, supporting initial media file processing (one-by-one) with metadata modifications, location processing, and interactive media uploads in subsequent turns. Handles large file uploads.
.DESCRIPTION
Initiates a conversation with Gemini. If -MediaFolder and -StartPrompt are provided for the first turn, it processes each supported file individually.
Supports optional metadata modification (-ModifyFiles, -UpdateTitle, -UpdateAuthor, -UpdateSubject, -UpdateTags, -UpdateRating, -UpdateDescription).
Supports location processing (-UpdateLocation) which reads GPS, prompts AI, updates filename, and writes metadata.
Subsequent turns allow text input and interactive uploading of media (folder or single file).
Uses Google AI File API for files larger than 20MB, otherwise uses inline data.
Requires ExifTool for modifications or location processing.

.PARAMETER ApiKey
Your Google Gemini API Key.
.PARAMETER Model
The Gemini model to use (e.g., 'gemini-1.5-flash-latest').
.PARAMETER StartPrompt
Required prompt for the first turn, especially if using -MediaFolder. Instructs Gemini on desired output format (Name:, Description:, Rating:, Tags:, Location:).
.PARAMETER MediaFolder
Optional folder containing media files to process one-by-one during the first turn. Requires -StartPrompt.
.PARAMETER RecurseFiles
Search -MediaFolder recursively.
.PARAMETER ModifyFiles
Enable renaming/updating files based on Gemini's response (requires -MediaFolder and ExifTool). Changes applied automatically by default.
.PARAMETER Confirm
[switch] If specified with -ModifyFiles, requires user confirmation before applying changes to each file.
.PARAMETER UpdateTitle, UpdateAuthor, UpdateSubject, UpdateTags, UpdateRating, UpdateDescription
[switch] Enable specific metadata updates (require -ModifyFiles).
.PARAMETER AuthorName
Author name for -UpdateAuthor.
.PARAMETER UpdateLocation
[switch] Enables location processing: Reads GPS (if available), prompts AI for location, parses 'Location:', updates filename (if -ModifyFiles), and writes City/State/Country metadata (if -ModifyFiles). Requires ExifTool.
.PARAMETER ExifToolPath
Optional. Full path to exiftool.exe if not in system PATH. Required if -ModifyFiles or -UpdateLocation is used and exiftool.exe is not in PATH.
.PARAMETER FileDelaySec
[int] Delay in seconds between processing each file in -MediaFolder. Defaults to 1.
.PARAMETER VertexProjectId
[string] Google Cloud Project ID for Vertex AI Image Generation. Required if using the /generate command.
.PARAMETER VertexLocationId
[string] Google Cloud Location ID (e.g., 'us-central1') for Vertex AI Image Generation. Required if using the /generate command.
.PARAMETER VertexDefaultOutputFolder
[string] Default output folder for images generated via /generate command. Required if using the /generate command.
.PARAMETER OutputFile
Optional file path to append prompts and responses.
.PARAMETER GenerationConfig, TimeoutSec, MaxRetries, InitialRetryDelaySec
Parameters for API call configuration and retry behavior.
.PARAMETER CsvOutputFile
Optional file path to export the full conversation history as a CSV file upon exiting.
.PARAMETER ResultsCsvFile
Optional file path to export the parsed Gemini results (Name, Description, etc.) for each processed file as a CSV.

.COMMANDS
/history      - Display conversation history.
/clear        - Clear conversation history.
/retry        - Retry the last failed API call.
/config       - Show current session settings.
/save         - Save history to CSV (if -CsvOutputFile specified).
/media [path] - Add media (folder/file) for the next prompt. If no path, prompts interactively.
/generate ... - Generate an image via Vertex AI.
/generate_from <path> - Describe image at <path> via Gemini, then generate a new image via Vertex AI using that description.
/image ...    - Alias for /generate.
/model <name> - Change the Gemini model for subsequent turns.
/exit         - Exit the chat session.
.EXAMPLE
PS C:\> $prompt = @"..." # Define your detailed prompt here
PS C:\> Start-GeminiChat -ApiKey $env:GEMINI_API_KEY -Model 'gemini-1.5-flash-latest' `
    -StartPrompt $prompt -MediaFolder "C:\MyPics" -ModifyFiles -UpdateTitle -UpdateDescription -UpdateTags -UpdateRating -UpdateLocation `
    -ExifToolPath "C:\Tools\exiftool.exe" -FileDelaySec 2 -OutputFile "C:\logs\gemini_unified_log.txt" -Verbose

.EXAMPLE
PS C:\> # Start interactive chat, then upload a large video
PS C:\> Start-GeminiChat -ApiKey $env:GEMINI_API_KEY -Model 'gemini-1.5-pro-latest'
# ... during chat ...
# You: /media C:\Videos\LargeVideo.mp4
# You (prompt for media): Summarize this video

.EXAMPLE
PS C:\> # Start chat session configured for image generation
PS C:\> Start-GeminiChat -ApiKey $env:GEMINI_API_KEY -VertexProjectId "your-gcp-project" -VertexLocationId "us-central1" -VertexDefaultOutputFolder "C:\GeneratedImages"
# Then, during the chat, type: /generate A cat wearing a superhero cape

.EXAMPLE
PS C:\> # Start chat and export history to CSV on exit
PS C:\> Start-GeminiChat -ApiKey $env:GEMINI_API_KEY -CsvOutputFile "C:\logs\chat_history.csv"

.EXAMPLE
PS C:\> # Process files and save parsed results to a separate CSV
PS C:\> Start-GeminiChat -ApiKey $env:GEMINI_API_KEY -StartPrompt $prompt -MediaFolder "C:\MyPics" -ResultsCsvFile "C:\logs\parsed_results.csv"
.OUTPUTS
[array] Returns the complete conversation history array upon exiting.
.NOTES
Version 3.5.5. Added /generate_from command.
Version 3.5.4. Added large file upload support via File API.
Version 3.5.3. Added /model display current model, /media path argument.
Version 3.5.2. Added /model command and -ResultsCsvFile parameter.
Version 3.5.1. Refined Location parsing regex. Added /save and /media commands. Added CSV export. Fixed initial message display. Modified /media command.
Version 3.5. Combined location processing into -UpdateLocation, added progress, fixed bugs.
Version 3.4. Renamed combined location switch back to -UpdateLocation.
Version 3.3. Enhanced parsing, ExifTool strategy, API response handling.
Version 3.2. Replaced TagLib# dependency with ExifTool for metadata operations. Requires exiftool.exe in PATH or via -ExifToolPath.
Version 3.1. Removed unreliable -SkipProcessedFiles feature.
Version 3.0. Unified script combining single-file processing, modifications, GPS, interactive uploads.
#>
# --- Google Photos API Helper Functions ---

function Get-GooglePhotosAccessToken {
    [CmdletBinding()]
    param()
    Write-Verbose "[Get-GooglePhotosAccessToken] Attempting to get access token via 'gcloud auth application-default print-access-token'..."
    $gcloudPath = Get-Command gcloud -ErrorAction SilentlyContinue
    if (-not $gcloudPath) {
        Write-Error "[Get-GooglePhotosAccessToken] Google Cloud SDK ('gcloud') not found in PATH. Please install and authenticate it (e.g., 'gcloud auth application-default login --scopes=https://www.googleapis.com/auth/photoslibrary.readonly,https://www.googleapis.com/auth/photoslibrary.sharing')."
        return $null
    }
    try {
        # Ensure --quiet is used to avoid interactive prompts if possible
        $accessToken = (gcloud auth application-default print-access-token --quiet --impersonate-service-account="") # Added impersonate flag often needed
        if ([string]::IsNullOrWhiteSpace($accessToken)) { throw "Received empty access token." }
        Write-Verbose "[Get-GooglePhotosAccessToken] Successfully obtained access token."
        return $accessToken
    } catch {
        Write-Error "[Get-GooglePhotosAccessToken] Failed to get access token using 'gcloud auth application-default print-access-token'. Ensure you are authenticated with required scopes (photoslibrary.readonly, photoslibrary.sharing). Error: $($_.Exception.Message)"
        return $null
    }
}

function Get-GooglePhotosAlbums {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$AccessToken
    )
    Write-Verbose "[Get-GooglePhotosAlbums] Fetching albums..."
    $apiUrl = "https://photoslibrary.googleapis.com/v1/albums?pageSize=50" # Max 50 per page
    $headers = @{ "Authorization" = "Bearer $AccessToken" }
    $albums = [System.Collections.ArrayList]::new()
    $nextPageToken = $null

    do {
        $currentUrl = $apiUrl
        if ($nextPageToken) { $currentUrl += "&pageToken=$nextPageToken" }
        try {
            Write-Verbose "[Get-GooglePhotosAlbums] Getting page: $currentUrl"
            $response = Invoke-RestMethod -Uri $currentUrl -Method Get -Headers $headers -ErrorAction Stop
            if ($response.albums) {
                $response.albums | ForEach-Object { [void]$albums.Add($_) }
            }
            $nextPageToken = $response.nextPageToken
        } catch {
            Write-Error "[Get-GooglePhotosAlbums] Failed to fetch albums page. Status: $($_.Exception.Response.StatusCode). Error: $($_.Exception.Message)"
            # Attempt to read error body
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                Write-Error "[Get-GooglePhotosAlbums] Error Body: $($reader.ReadToEnd())"
                $reader.Close()
            } catch { Write-Warning "[Get-GooglePhotosAlbums] Could not read error response body."}
            return $null # Stop fetching on error
        }
    } while ($nextPageToken)

    Write-Verbose "[Get-GooglePhotosAlbums] Found $($albums.Count) albums."
    return $albums
}

function Get-GooglePhotosMediaItems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$AccessToken,
        [Parameter(ParameterSetName='Album')][string]$AlbumId,
        [Parameter(ParameterSetName='Search')][hashtable]$SearchFilter, # e.g., @{ dateFilter = @{ ranges = @(@{startDate=@{year=2024;month=1;day=1};endDate=@{year=2024;month=1;day=31}}) } }
        [int]$PageSize = 100 # Max 100 per page
    )
    Write-Verbose "[Get-GooglePhotosMediaItems] Fetching media items..."
    $apiUrl = "https://photoslibrary.googleapis.com/v1/mediaItems:search"
    $headers = @{ "Authorization" = "Bearer $AccessToken"; "Content-Type" = "application/json" }
    $mediaItems = [System.Collections.ArrayList]::new()
    $nextPageToken = $null
    $requestBody = @{ pageSize = $PageSize }

    if ($PSCmdlet.ParameterSetName -eq 'Album') {
        $requestBody.albumId = $AlbumId
        Write-Verbose "[Get-GooglePhotosMediaItems] Searching in Album ID: $AlbumId"
    } elseif ($PSCmdlet.ParameterSetName -eq 'Search') {
        $requestBody.filters = $SearchFilter
        Write-Verbose "[Get-GooglePhotosMediaItems] Searching with Filter: $($SearchFilter | ConvertTo-Json -Depth 5 -Compress)"
    } else {
         Write-Error "[Get-GooglePhotosMediaItems] Either -AlbumId or -SearchFilter must be specified."
         return $null
    }

    do {
        if ($nextPageToken) { $requestBody.pageToken = $nextPageToken }
        else { $requestBody.Remove('pageToken') } # Ensure not present on first request

        $bodyJson = $requestBody | ConvertTo-Json -Depth 10
        try {
            Write-Verbose "[Get-GooglePhotosMediaItems] Posting search request..."
            $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $bodyJson -ErrorAction Stop
            if ($response.mediaItems) {
                $response.mediaItems | ForEach-Object { [void]$mediaItems.Add($_) }
                Write-Verbose "[Get-GooglePhotosMediaItems] Fetched $($response.mediaItems.Count) items this page. Total: $($mediaItems.Count)"
            } else {
                 Write-Verbose "[Get-GooglePhotosMediaItems] No media items found on this page."
            }
            $nextPageToken = $response.nextPageToken
        } catch {
            Write-Error "[Get-GooglePhotosMediaItems] Failed to fetch media items page. Status: $($_.Exception.Response.StatusCode). Error: $($_.Exception.Message)"
             try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                Write-Error "[Get-GooglePhotosMediaItems] Error Body: $($reader.ReadToEnd())"
                $reader.Close()
            } catch { Write-Warning "[Get-GooglePhotosMediaItems] Could not read error response body."}
            return $null # Stop fetching on error
        }
    } while ($nextPageToken)

    Write-Verbose "[Get-GooglePhotosMediaItems] Found $($mediaItems.Count) total media items."
    return $mediaItems
}

function Update-GooglePhotosDescription {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory = $true)][string]$AccessToken,
        [Parameter(Mandatory = $true)][string]$MediaItemId,
        [Parameter(Mandatory = $true)][string]$NewDescription
    )
    Write-Verbose "[Update-GooglePhotosDescription] Updating description for MediaItemId: $MediaItemId"
    $apiUrl = "https://photoslibrary.googleapis.com/v1/mediaItems/$MediaItemId`?updateMask=description"
    $headers = @{ "Authorization" = "Bearer $AccessToken"; "Content-Type" = "application/json" }
    $requestBody = @{ description = $NewDescription } | ConvertTo-Json

    if ($PSCmdlet.ShouldProcess($MediaItemId, "Update Description to '$($NewDescription.Substring(0,[System.Math]::Min($NewDescription.Length, 50)))...'")) {
        try {
            $response = Invoke-RestMethod -Uri $apiUrl -Method Patch -Headers $headers -Body $requestBody -ErrorAction Stop
            Write-Host "[Google Photos Description Updated: $MediaItemId]" -ForegroundColor DarkGreen
            return $true
        } catch {
            Write-Error "[Update-GooglePhotosDescription] Failed to update description for $MediaItemId. Status: $($_.Exception.Response.StatusCode). Error: $($_.Exception.Message)"
             try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                Write-Error "[Update-GooglePhotosDescription] Error Body: $($reader.ReadToEnd())"
                $reader.Close()
            } catch { Write-Warning "[Update-GooglePhotosDescription] Could not read error response body."}
            return $false
        }
    } else {
        Write-Warning "[Update-GooglePhotosDescription] Update skipped due to -WhatIf or user confirmation."
        return $false
    }
}
# --- End Google Photos API Helper Functions ---

function Start-GeminiChat {
    [CmdletBinding()]
    param(
        # --- Core Parameters ---
        [Parameter(HelpMessage = "Your Google Gemini API Key.")] [string]$ApiKey,
        [Parameter(HelpMessage = "The Gemini model to use.")] [string]$Model = 'gemini-1.5-pro-latest',
        [Parameter(HelpMessage = "Optional hashtable for generation configuration.")] [hashtable]$GenerationConfig,
        [Parameter(HelpMessage = "Timeout for API requests in seconds.")] [int]$TimeoutSec = 300,
        [Parameter(HelpMessage = "Max retries on HTTP 429 errors within API calls.")] [ValidateRange(0, 5)] [int]$MaxRetries = 3,
        [Parameter(HelpMessage = "Initial delay for HTTP 429 retries (seconds).")] [ValidateRange(1, 60)] [int]$InitialRetryDelaySec = 2,

        # --- File Processing Delay ---
        [Parameter(HelpMessage = "Delay in seconds between processing each file when using -MediaFolder.")] [ValidateRange(0, 60)] [int]$FileDelaySec = 1,

        # --- First Turn / Media Parameters ---
        [Parameter(HelpMessage = "Optional prompt for the first turn. REQUIRED if -MediaFolder is used.")] [string]$StartPrompt,
        [Parameter(HelpMessage = "Optional folder containing media for the first turn (processed one-by-one).")] [ValidateScript({ Test-Path -Path $_ -PathType Container })] [string]$MediaFolder,
        [Parameter(HelpMessage = "Recurse media folder.")] [switch]$RecurseFiles,

        # --- Modification Parameters ---
        [Parameter(HelpMessage = "Enable renaming/updating initial files based on response. Requires -MediaFolder & ExifTool. Changes applied automatically by default.")] [switch]$ModifyFiles,
        [Parameter(HelpMessage = "If specified with -ModifyFiles, requires user confirmation before applying changes.")] [switch]$Confirm,
        [Parameter(HelpMessage = "Update 'Title' metadata (requires -ModifyFiles).")] [switch]$UpdateTitle,
        [Parameter(HelpMessage = "Replace 'Creator'/'Artist' metadata (requires -ModifyFiles, -AuthorName).")] [switch]$UpdateAuthor,
        [Parameter(Mandatory = $false, HelpMessage = "Author name for -UpdateAuthor.")] [string]$AuthorName,
        [Parameter(HelpMessage = "Update 'Comment' metadata from Title (requires -ModifyFiles).")] [switch]$UpdateSubject,
        [Parameter(HelpMessage = "Parse 'Tags:'/'Keywords:' and overwrite metadata (requires -ModifyFiles & ExifTool).")] [switch]$UpdateTags,
        [Parameter(HelpMessage = "Parse 'Rating:' and update metadata/append to filename (requires -ModifyFiles).")] [switch]$UpdateRating,
        [Parameter(HelpMessage = "Enables location processing: Reads GPS, prompts AI, parses 'Location:', updates filename (if -ModifyFiles), and writes City/State/Country metadata (if -ModifyFiles). Requires ExifTool.")] [switch]$UpdateLocation, # Renamed back
        [Parameter(HelpMessage = "Parse 'Description:' and update metadata (requires -ModifyFiles).")] [switch]$UpdateDescription,
        [Parameter(HelpMessage="Optional. Full path to exiftool.exe if not in system PATH.")] [string]$ExifToolPath,

        # --- Other Parameters ---
        [Parameter(HelpMessage = "Optional file to append Gemini prompts and responses.")] [string]$OutputFile,

        # --- Vertex AI Image Generation Parameters ---
        [Parameter(HelpMessage="Google Cloud Project ID for Vertex AI Image Generation via /generate command.")] [string]$VertexProjectId,
        [Parameter(HelpMessage="Google Cloud Location ID (e.g., 'us-central1') for Vertex AI Image Generation via /generate command.")] [string]$VertexLocationId,
        [Parameter(HelpMessage="Default output folder for images generated via /generate command.")] [string]$VertexDefaultOutputFolder,
        # --- NEW CSV PARAMETER ---
        [Parameter(HelpMessage="Optional file path to export the full conversation history as a CSV file upon exiting.")] [string]$CsvOutputFile,
        # --- NEW RESULTS CSV PARAMETER ---
        [Parameter(HelpMessage="Optional file path to save the parsed Gemini results (Name, Description, Tags, etc.) for each processed file as a CSV.")] [string]$ResultsCsvFile
    )
        # --- Google Photos Parameters ---
        [Parameter(ParameterSetName='GooglePhotosAlbum', HelpMessage="Process media items from a specific Google Photos Album ID instead of a local folder.")]
        [string]$GooglePhotosAlbumId,
        [Parameter(ParameterSetName='GooglePhotosSearch', HelpMessage="Process media items matching a Google Photos search filter hashtable instead of a local folder.")]
        [hashtable]$GooglePhotosSearchFilter

    # --- Verbose Preference Handling ---
    $originalVerbosePreference = $VerbosePreference
    if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { $VerbosePreference = 'Continue'; Write-Host "[Start-GeminiChat] -Verbose switch detected. Setting `$VerbosePreference = 'Continue'." -ForegroundColor DarkGray }
    else { Write-Host "[Start-GeminiChat] -Verbose switch NOT detected. `$VerbosePreference = '$originalVerbosePreference'." -ForegroundColor DarkGray }
    Write-Verbose "[Debug] Bound Keys at Start: $($PSCmdlet.MyInvocation.BoundParameters.Keys -join ', ')"

    # --- Parameter Validation ---
    # Ensure StartPrompt is provided if any initial processing (local or Google Photos) is requested
    if (($PSBoundParameters.ContainsKey('MediaFolder') -or $PSBoundParameters.ContainsKey('GooglePhotosAlbumId') -or $PSBoundParameters.ContainsKey('GooglePhotosSearchFilter')) `
        -and (-not $PSBoundParameters.ContainsKey('StartPrompt') -or [string]::IsNullOrWhiteSpace($StartPrompt))) {
        throw "-StartPrompt is required and cannot be empty when using -MediaFolder, -GooglePhotosAlbumId, or -GooglePhotosSearchFilter."
    }

    $anyUpdateSwitch = $UpdateTitle.IsPresent -or $UpdateAuthor.IsPresent -or $UpdateSubject.IsPresent -or $UpdateTags.IsPresent -or $UpdateRating.IsPresent -or $UpdateLocation.IsPresent -or $UpdateDescription.IsPresent # Use UpdateLocation here
    if ($anyUpdateSwitch -and -not $ModifyFiles.IsPresent) { Write-Warning "Metadata update switches (-Update*) ignored without -ModifyFiles." }
    if ($ModifyFiles.IsPresent -and -not $PSBoundParameters.ContainsKey('MediaFolder')) { Write-Warning "-ModifyFiles requires -MediaFolder. Disabling modifications."; $ModifyFiles = $false } # Disable if no folder
    if ($UpdateAuthor.IsPresent -and [string]::IsNullOrWhiteSpace($AuthorName)) { throw "-AuthorName is required when -UpdateAuthor is specified." }
    if ($UpdateLocation.IsPresent -and -not $ModifyFiles.IsPresent) { Write-Warning "-UpdateLocation specified without -ModifyFiles. Location will be read and prompted, but not written to filename/metadata." }
    if ($UpdateDescription.IsPresent -and -not $ModifyFiles.IsPresent) { Write-Warning "-UpdateDescription ignored without -ModifyFiles." }
    if ($Confirm.IsPresent -and -not $ModifyFiles.IsPresent) { Write-Warning "-Confirm ignored without -ModifyFiles." }
    if (($PSBoundParameters.ContainsKey('VertexProjectId') -or $PSBoundParameters.ContainsKey('VertexLocationId') -or $PSBoundParameters.ContainsKey('VertexDefaultOutputFolder')) -and
        (-not $PSBoundParameters.ContainsKey('VertexProjectId') -or -not $PSBoundParameters.ContainsKey('VertexLocationId') -or -not $PSBoundParameters.ContainsKey('VertexDefaultOutputFolder'))) {
        Write-Warning "Vertex AI image generation requires all three parameters: -VertexProjectId, -VertexLocationId, and -VertexDefaultOutputFolder."
    }
    # --- NEW: Validate CSV Output Path ---
    if ($PSBoundParameters.ContainsKey('CsvOutputFile') -and -not ([string]::IsNullOrWhiteSpace($CsvOutputFile))) {
        try {
            $csvDir = Split-Path -Path $CsvOutputFile -Parent -EA Stop
            if (-not (Test-Path -Path $csvDir -PathType Container)) { Write-Warning "Creating CSV output directory: $csvDir"; New-Item -Path $csvDir -ItemType Directory -Force -EA Stop | Out-Null; Write-Verbose "Created CSV output directory." }
            # Test write access by attempting to create/append an empty line
            "" | Out-File -FilePath $CsvOutputFile -Append -Encoding UTF8 -ErrorAction Stop
            Write-Verbose "CSV output path appears valid: $CsvOutputFile"
        } catch { Write-Error "Invalid -CsvOutputFile path or cannot create/write to directory: '$CsvOutputFile'. Error: $($_.Exception.Message)"; return }
    }
    # --- NEW: Validate ResultsCsvFile Path ---
    if ($PSBoundParameters.ContainsKey('ResultsCsvFile') -and -not ([string]::IsNullOrWhiteSpace($ResultsCsvFile))) {
        try {
            $resultsDir = Split-Path -Path $ResultsCsvFile -Parent -EA Stop
            if (-not (Test-Path -Path $resultsDir -PathType Container)) { Write-Warning "Creating results CSV output directory: $resultsDir"; New-Item -Path $resultsDir -ItemType Directory -Force -EA Stop | Out-Null; Write-Verbose "Created results CSV output directory." }
            # Test write access by attempting to create/append an empty line
            "" | Out-File -FilePath $ResultsCsvFile -Append -Encoding UTF8 -ErrorAction Stop
            Write-Verbose "Results CSV output path appears valid: $ResultsCsvFile"
        } catch { Write-Error "Invalid -ResultsCsvFile path or cannot create/write to directory: '$ResultsCsvFile'. Error: $($_.Exception.Message)"; return }
    }
    # --- End CSV Validation ---
    if ($PSBoundParameters.ContainsKey('OutputFile') -and -not ([string]::IsNullOrWhiteSpace($OutputFile))) { try { $outputDir = Split-Path -Path $OutputFile -Parent -EA Stop; if (-not (Test-Path -Path $outputDir -PathType Container)) { Write-Warning "Creating output directory: $outputDir"; New-Item -Path $outputDir -ItemType Directory -Force -EA Stop | Out-Null; Write-Verbose "Created output directory." } } catch { Write-Error "Invalid -OutputFile path or cannot create directory: '$OutputFile'. Error: $($_.Exception.Message)"; return } }

    # --- Check for ExifTool ---
    $resolvedExifToolPath = $null
    if ($ModifyFiles.IsPresent -or $UpdateLocation.IsPresent) { # Check if needed for Modify or UpdateLocation
        if ($PSBoundParameters.ContainsKey('ExifToolPath')) {
            # Check if it's the executable file directly
            if ((Test-Path -LiteralPath $ExifToolPath -PathType Leaf) -and ($ExifToolPath -like '*exiftool.exe')) { # Corrected syntax
                $resolvedExifToolPath = $ExifToolPath
                Write-Verbose "Using ExifTool specified by parameter: $resolvedExifToolPath"
            # Check if it's a folder containing the executable
            } elseif (Test-Path -LiteralPath $ExifToolPath -PathType Container) {
                $potentialPath = Join-Path -Path $ExifToolPath -ChildPath 'exiftool.exe'
                if (Test-Path -LiteralPath $potentialPath -PathType Leaf) {
                    $resolvedExifToolPath = $potentialPath
                    Write-Verbose "Found exiftool.exe within specified folder: $resolvedExifToolPath"
                } else { Write-Warning "ExifTool path specified via -ExifToolPath is a folder, but does not contain 'exiftool.exe': '$ExifToolPath'. Falling back to PATH search." }
            } else {
                Write-Warning "ExifTool path specified via -ExifToolPath is not a valid file or folder containing exiftool.exe: '$ExifToolPath'. Falling back to PATH search."
            }
        }
        if (-not $resolvedExifToolPath) {
            $exifToolCmd = Get-Command exiftool.exe -ErrorAction SilentlyContinue
            if ($exifToolCmd) { $resolvedExifToolPath = $exifToolCmd.Path; Write-Verbose "Using ExifTool found in PATH: $resolvedExifToolPath" }
        }
        if (-not $resolvedExifToolPath) {
            Write-Error "ExifTool not found via -ExifToolPath parameter or in system PATH. It is required for -ModifyFiles or -UpdateLocation. Download from https://exiftool.org/."
            if ($ModifyFiles.IsPresent) { Write-Warning "Disabling -ModifyFiles because ExifTool was not found."; $ModifyFiles = $false }
            if ($UpdateLocation.IsPresent) { Write-Warning "Disabling -UpdateLocation because ExifTool was not found."; $UpdateLocation = $false }
        }
    }

    # --- API Key Check ---
    if ([string]::IsNullOrWhiteSpace($ApiKey)) { Write-Host "API Key is required." -ForegroundColor Yellow; try { $secureApiKey = Read-Host "Enter your Google Gemini API Key" -AsSecureString; if ($secureApiKey -ne $null -and $secureApiKey.Length -gt 0) { $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureApiKey); $ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr); [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) } else { Write-Error "API Key cannot be empty."; return } } catch { Write-Error "Failed to read API Key: $($_.Exception.Message)"; return } }

    # --- Store Session Configuration for /config command ---
    $sessionConfig = @{
        Model                     = $Model
        TimeoutSec                = $TimeoutSec
        MaxRetries                = $MaxRetries
        InitialRetryDelaySec      = $InitialRetryDelaySec
        FileDelaySec              = $FileDelaySec
        MediaFolder               = $MediaFolder
        RecurseFiles              = $RecurseFiles.IsPresent
        ModifyFiles               = $ModifyFiles.IsPresent
        ConfirmModifications      = $Confirm.IsPresent
        UpdateTitle               = $UpdateTitle.IsPresent
        UpdateAuthor              = $UpdateAuthor.IsPresent
        AuthorName                = $AuthorName
        UpdateSubject             = $UpdateSubject.IsPresent
        UpdateTags                = $UpdateTags.IsPresent
        UpdateRating              = $UpdateRating.IsPresent
        UpdateLocation            = $UpdateLocation.IsPresent
        UpdateDescription         = $UpdateDescription.IsPresent
        ExifToolPath              = $resolvedExifToolPath
        OutputFile                = $OutputFile
        CsvOutputFile             = $CsvOutputFile # Store CSV path
        ResultsCsvFile            = $ResultsCsvFile # Store results CSV path
        VertexProjectId           = $VertexProjectId
        VertexLocationId          = $VertexLocationId
        VertexDefaultOutputFolder = $VertexDefaultOutputFolder
        GooglePhotosAlbumId       = $GooglePhotosAlbumId # Add GP params
        GooglePhotosSearchFilter  = $GooglePhotosSearchFilter
        GenerationConfig          = $GenerationConfig # Store GenerationConfig hashtable
        Verbose                   = $VerbosePreference -eq 'Continue' # Store verbose state
    }

    # --- NEW: Vertex AI Parameter Warning ---
    if (-not ($sessionConfig.VertexProjectId -and $sessionConfig.VertexLocationId -and $sessionConfig.VertexDefaultOutputFolder)) {
        Write-Warning "Vertex AI image generation parameters (-VertexProjectId, -VertexLocationId, -VertexDefaultOutputFolder) are not fully specified. The '/generate' command will not function."
    }
    # --- End Warning ---

    # --- Initial Messages ---
    Write-Host "`nWelcome to the Unified Gemini Chat Script!" -ForegroundColor Cyan
    Write-Host "This script allows interactive chat, optional initial file processing with metadata modification, and Vertex AI image generation." -ForegroundColor Gray
    Write-Host "Starting Unified Gemini chat session (Mods Enabled: $($ModifyFiles.IsPresent))." -ForegroundColor Cyan
    Write-Host "Using model: $($sessionConfig.Model)" -ForegroundColor Cyan # Use session config
    $activeFlagsList = [System.Collections.Generic.List[string]]::new(); $boundParams = $PSCmdlet.MyInvocation.BoundParameters
    # Dynamically build list of active boolean switches and parameters with values
    foreach ($key in ($boundParams.Keys | Sort-Object)) { # Sort for consistent order
        $param = $PSCmdlet.MyInvocation.MyCommand.Parameters[$key]
        if ($param.ParameterType -eq [switch]) {
            if ($boundParams[$key]) { $activeFlagsList.Add("-$key") }
        } elseif ($key -notin @('ApiKey', 'StartPrompt')) { # Exclude sensitive/long params from this list
             if ($boundParams[$key]) { $activeFlagsList.Add("-$key") } # Only add if value is not $null/empty
        }
    }
    if ($activeFlagsList.Count -gt 0) { $flagsString = ($activeFlagsList | Sort-Object -Unique | Where-Object { $_ }) -join ', '; Write-Host "Active Flags: $flagsString" -ForegroundColor Cyan } else { Write-Host "Active Flags: None" -ForegroundColor Cyan }
    if ($ModifyFiles.IsPresent) { Write-Host "File Modifications Enabled (Requires ExifTool)." -ForegroundColor Yellow; if ($Confirm.IsPresent) { Write-Host "Confirmation WILL be required before applying changes." -ForegroundColor Yellow } else { Write-Host "Changes applied AUTOMATICALLY (Use -Confirm to prompt)." -ForegroundColor Yellow } }
    if ($UpdateLocation.IsPresent) { Write-Host "Location Processing Enabled (Read GPS, Prompt AI, Update Metadata/Filename). Requires ExifTool." -ForegroundColor Yellow }
    if ($UpdateDescription.IsPresent) { Write-Host "Description Update Enabled (Requires ExifTool)." -ForegroundColor Yellow }
    if ($PSBoundParameters.ContainsKey('MediaFolder') -and $FileDelaySec -gt 0) { Write-Host "Delaying $FileDelaySec second(s) between file processing." -ForegroundColor Cyan }
    if ($PSBoundParameters.ContainsKey('VertexProjectId')) { Write-Host "Vertex AI Image Generation configured (use /generate or /image command)." -ForegroundColor Cyan }
    if ($PSBoundParameters.ContainsKey('ResultsCsvFile') -and -not ([string]::IsNullOrWhiteSpace($ResultsCsvFile))) { Write-Host "Parsed results will be saved to: $ResultsCsvFile" -ForegroundColor Cyan } # Added message
    if ($PSBoundParameters.ContainsKey('CsvOutputFile') -and -not ([string]::IsNullOrWhiteSpace($CsvOutputFile))) { Write-Host "Chat history will be exported to: $CsvOutputFile (on exit or /save)" -ForegroundColor Cyan } # Updated CSV message
    if ($PSBoundParameters.ContainsKey('OutputFile') -and -not ([string]::IsNullOrWhiteSpace($OutputFile))) { Write-Host "Appending prompts and responses to: $OutputFile" -ForegroundColor Cyan }
    if ($PSBoundParameters.ContainsKey('GooglePhotosAlbumId') -or $PSBoundParameters.ContainsKey('GooglePhotosSearchFilter')) { Write-Host "Google Photos processing mode enabled. Ensure 'gcloud' is authenticated." -ForegroundColor Yellow }
    # Command list moved to first prompt section
    Write-Host "------------------------------------------" -ForegroundColor Cyan

    $conversationHistory = @() # Initialize history array
    $isFirstTurn = $true
    # --- Variables for /retry ---
    $lastUserPrompt = $null
    $lastApiResult = $null
    $globalRenameErrors = [System.Collections.ArrayList]::new()
    $globalMetadataErrors = [System.Collections.ArrayList]::new()

    try {
        while ($true) {
            # --- Reset Turn Variables ---
            $currentPromptInput = $null; $apiResult = $null
            $currentImageFolder = $null; $currentVideoFolder = $null; $currentRecurse = $false; $currentInlineFilePaths = $null # Reset interactive media vars
            $skipApiCall = $false # Flag to skip API call if a command handles the turn

            # --- Get User Input / First Turn File Processing ---
            if ($isFirstTurn) {
                # --- Initial Processing Logic ---
                $processLocally = $PSBoundParameters.ContainsKey('MediaFolder') -and $PSBoundParameters.ContainsKey('StartPrompt')
                $processGooglePhotos = ($PSBoundParameters.ContainsKey('GooglePhotosAlbumId') -or $PSBoundParameters.ContainsKey('GooglePhotosSearchFilter')) -and $PSBoundParameters.ContainsKey('StartPrompt')
                $basePrompt = $StartPrompt; $processedFileCount = 0; $skippedFileCount = 0

                if ($processLocally) {
                    # --- Process LOCAL Files One-by-One ---
                    $currentMediaFolder = $MediaFolder; $currentRecurse = $RecurseFiles.IsPresent;
                    Write-Host "`nProcessing LOCAL files in '$currentMediaFolder'$($currentRecurse ? ' (Recursive)' : '') using StartPrompt..." -ForegroundColor Yellow; Write-Host "Base Start Prompt: $basePrompt" -ForegroundColor White
                    $imageExtensionsForGPS = @('.jpg', '.jpeg', '.heic', '.heif', '.tiff', '.tif')
                    $discoveredFiles = [System.Collections.ArrayList]::new(); Write-Verbose "Discovering initial files..."
                    # Define supported extensions for different media types
                    $supportedExtensionsMap = @{
                        image    = @('.jpg','.jpeg','.png','.webp','.gif','.heic','.heif','.bmp','.tif','.tiff')
                        video    = @('.mp4','.mpeg','.mov','.avi','.flv','.mpg','.webm','.wmv','.3gp','.3gpp','.mkv')
                        audio    = @('.mp3','.wav','.ogg','.flac','.m4a','.aac','.wma')
                        document = @('.txt','.pdf','.html','.htm','.json','.csv','.xml','.rtf','.md')
                    }
                    $mediaTypes = $supportedExtensionsMap.Keys
                    foreach ($mediaType in $mediaTypes) {
                        $found = Get-StartMediaFiles -FolderPath $currentMediaFolder -Recurse:$RecurseFiles -SupportedExtensions $supportedExtensionsMap[$mediaType] -MediaType $mediaType
                        if ($null -ne $found -and $found.Count -gt 0) {
                            Write-Host "($($found.Count) starting $($mediaType) file(s) found)" -ForegroundColor Gray
                            # --- Modification Start: Skip OutputFile ---
                            $found | ForEach-Object {
                                if ($PSBoundParameters.ContainsKey('OutputFile') -and ($_.FullName -eq (Resolve-Path -LiteralPath $OutputFile -ErrorAction SilentlyContinue))) { Write-Verbose "  Skipping log file: $($_.Name)" }
                                else { [void]$discoveredFiles.Add($_) }
                            }
                            # --- Modification End ---
                        }
                    }

                    if ($discoveredFiles.Count -eq 0) { Write-Warning "No supported files found in '$currentMediaFolder'." }
                    else {
                        $fileIndex = 0
                        foreach ($fileInfo in $discoveredFiles) {
                            $fileIndex++; $filePath = $fileInfo.FullName
                            Write-Host "`nProcessing LOCAL File $fileIndex of $($discoveredFiles.Count): $($fileInfo.Name)" -ForegroundColor Cyan

                            # --- Read GPS and Modify Prompt ---
                            $promptForThisFile = $basePrompt; $gpsCoordsString = $null
                            # Check if ExifTool is available and location processing is requested
                            if ($resolvedExifToolPath -and $UpdateLocation.IsPresent -and ($imageExtensionsForGPS -contains $fileInfo.Extension.ToLowerInvariant())) { # Check UpdateLocation
                                try {
                                    Write-Verbose "  Attempting to read GPS using ExifTool..."
                                    # Call ExifTool, capture stdout to $exifToolOutput, stderr to $exifError
                                    $exifToolArgs = @('-n', '-GPSLatitude', '-GPSLongitude', '-j', '-coordFormat', '%.6f', $filePath)
                                    $process = Start-Process -FilePath $resolvedExifToolPath -ArgumentList $exifToolArgs -Wait -NoNewWindow -RedirectStandardOutput ($stdOutFile = New-TemporaryFile) -RedirectStandardError ($stdErrFile = New-TemporaryFile) -PassThru
                                    $exifToolOutput = Get-Content -Path $stdOutFile.FullName
                                    $exifError = Get-Content -Path $stdErrFile.FullName
                                    Remove-Item $stdOutFile.FullName, $stdErrFile.FullName -ErrorAction SilentlyContinue
                                    Write-Verbose "  ExifTool GPS Read StdOut: $($exifToolOutput -join "`n  ")"
                                    if ($process.ExitCode -ne 0 -or $exifError) { throw "ExifTool exited with code $($process.ExitCode). Stderr: $($exifError -join '; ')" }
                                    $exifOutputJson = $exifToolOutput -join "" # Join lines in case output is split
                                    $exifData = $exifOutputJson | ConvertFrom-Json -ErrorAction SilentlyContinue

                                    # ExifTool returns an array even for one file
                                    if ($exifData -is [array]) { $exifData = $exifData[0] }

                                    if ($exifData -ne $null -and $exifData.PSObject.Properties.Name -contains 'GPSLatitude' -and $exifData.PSObject.Properties.Name -contains 'GPSLongitude' -and $exifData.GPSLatitude -ne 0 -and $exifData.GPSLongitude -ne 0) {
                                        # Format GPS coordinates
                                        $lat = $exifData.GPSLatitude.ToString("F6", [System.Globalization.CultureInfo]::InvariantCulture)
                                        $lon = $exifData.GPSLongitude.ToString("F6", [System.Globalization.CultureInfo]::InvariantCulture) # Already formatted by -coordFormat "%.6f"
                                        $gpsCoordsString = "GPS: $lat, $lon"
                                        Write-Verbose "  Found GPS via ExifTool: $gpsCoordsString"
                                    } else {
                                        Write-Verbose "  No valid GPS Latitude/Longitude found via ExifTool."
                                    }
                                } catch { Write-Warning "  Error reading/parsing GPS metadata for '$($fileInfo.Name)': $($_.Exception.Message)." } # Error message now includes stderr
                            } elseif ($UpdateLocation.IsPresent -and -not $resolvedExifToolPath) { Write-Warning "  Cannot read GPS (-UpdateLocation) - ExifTool not found." } elseif ($UpdateLocation.IsPresent) { Write-Verbose "  Skipping GPS read (-UpdateLocation) (not a supported image type or ExifTool unavailable)." } else { Write-Verbose "  Skipping GPS read (-UpdateLocation not specified)." }
                            if ($gpsCoordsString -ne $null -and $UpdateLocation.IsPresent) { $locationInstruction = "`n5. Based on these coordinates ($gpsCoordsString), determine the location (City, State/Province, Country) and prefix it with 'Location:'. Example: Location: San Francisco, CA, USA"; $promptForThisFile += $locationInstruction; Write-Verbose "  Appended GPS location instruction to prompt." }
                            # --- End GPS ---

                            # --- API Call for this file ---
                            $invokeParams = @{ ApiKey = $ApiKey; Model = $sessionConfig.Model; TimeoutSec = $TimeoutSec; MaxRetries = $MaxRetries; InitialRetryDelaySec = $InitialRetryDelaySec; Prompt = $promptForThisFile; InlineFilePaths = @($filePath); ConversationHistory= @() }; if ($PSBoundParameters.ContainsKey('GenerationConfig')) { $invokeParams.GenerationConfig = $GenerationConfig } # Use sessionConfig.Model
                            Write-Host "[DEBUG] Sending Prompt to Gemini (File: $($fileInfo.Name)):`n$($invokeParams.Prompt)" -ForegroundColor DarkYellow; Write-Host "Gemini is thinking..." -ForegroundColor DarkGray
                            $timerJob = Start-Job -ScriptBlock { Start-Sleep -Seconds 3600 }; try { $apiResult = Invoke-GeminiApi @invokeParams } finally { Stop-Job -Job $timerJob -EA SilentlyContinue; Remove-Job -Job $timerJob -Force -EA SilentlyContinue; Write-Host "`r".PadRight([Console]::WindowWidth - 1); Write-Host "`r" -NoNewline }

                            # --- Progress Bar Update ---
                            Write-Progress -Activity "Processing Media Files" -Status "Processing '$($fileInfo.Name)' ($fileIndex/$($discoveredFiles.Count))" -PercentComplete (($fileIndex / $discoveredFiles.Count) * 100)

                            # --- Process Result for this file ---
                            if ($apiResult -ne $null -and $apiResult.Success) {
                                Write-Host "Gemini Response (File: $($fileInfo.Name)):" -ForegroundColor Green; Write-Host $apiResult.GeneratedText -ForegroundColor Green
                                if ($PSBoundParameters.ContainsKey('OutputFile')) { try { $outputContent = "`n--- File '$($fileInfo.Name)' ($(Get-Date)) ---`nPROMPT:`n$($invokeParams.Prompt)`n`nRESPONSE:`n$($apiResult.GeneratedText)`n"; $outputContent | Out-File -FilePath $OutputFile -Append -Encoding UTF8 -EA Stop; Write-Verbose "Appended response to log." } catch { Write-Warning "Failed append response to '$OutputFile': $($_.Exception.Message)" } }

                                # --- Parse Response ---
                                $parsedData = Parse-GeminiResponse -GeminiText $apiResult.GeneratedText

                                # --- Modification Logic ---
                                if ($ModifyFiles.IsPresent -and $resolvedExifToolPath) { # Check for ExifTool
                                    Write-Verbose "Attempting modifications for '$($fileInfo.Name)'...";

                                    $proceedWithModify = $false; $proposalMade = $false; $proposedChangesList = [System.Collections.ArrayList]::new(); $originalExtension = $fileInfo.Extension; $originalFileNameBase = [System.IO.Path]::GetFileNameWithoutExtension($fileInfo.Name)
                                    # Build the new filename parts
                                    $sanitizedNamePart = if ($parsedData.Name) { Sanitize-Filename -InputString $parsedData.Name } else { $null }
                                    $sanitizedLocationPart = if ($UpdateLocation.IsPresent -and $parsedData.Location) { Sanitize-Filename -InputString $parsedData.Location -MaxLength 50 } else { $null } # Check UpdateLocation
                                    $ratingPart = if ($UpdateRating.IsPresent -and $parsedData.Rating -ne $null) { $parsedData.Rating } else { $null }
                                    $newNameParts = [System.Collections.ArrayList]::new()
                                    # Add Name (or original base name if Name wasn't parsed)
                                    if ($sanitizedNamePart) { [void]$newNameParts.Add($sanitizedNamePart) } else { [void]$newNameParts.Add($originalFileNameBase) }
                                    # Add Location IF it was sanitized (meaning -UpdateLocation was present and $parsedData.Location had a value)
                                    if ($sanitizedLocationPart) { [void]$newNameParts.Add($sanitizedLocationPart) }
                                    # Add Rating IF it was parsed and -UpdateRating is present
                                    if ($ratingPart -ne $null) { [void]$newNameParts.Add($ratingPart) }
                                    # Failsafe if somehow all parts ended up null
                                    if ($newNameParts.Count -eq 0) { [void]$newNameParts.Add($originalFileNameBase) }
                                    $newNameBase = $newNameParts -join '_'; $newName = "{0}{1}" -f $newNameBase, $originalExtension; $newPath = Join-Path -Path $fileInfo.DirectoryName -ChildPath $newName

                                    # Determine if changes are actually proposed
                                    $isRenameProposed = ($newName -ne $fileInfo.Name)
                                    $isMetadataUpdateProposed = $anyUpdateSwitch # Already includes UpdateLocation check from earlier
                                    $hasDataForProposedMetadata = ($UpdateTitle.IsPresent -and $parsedData.Name) -or
                                                                  ($UpdateAuthor.IsPresent -and $PSBoundParameters.ContainsKey('AuthorName')) -or
                                                                  ($UpdateSubject.IsPresent -and $parsedData.Name) -or
                                                                  ($UpdateTags.IsPresent -and $parsedData.Tags.Count -gt 0) -or
                                                                  ($UpdateRating.IsPresent -and $parsedData.Rating -ne $null) -or
                                                                  ($UpdateDescription.IsPresent -and $parsedData.Description) -or
                                                                  ($UpdateLocation.IsPresent -and $parsedData.Location) # Check UpdateLocation for metadata

                                    # Propose changes if rename is needed OR metadata update is requested AND we have data for it
                                    if ($isRenameProposed -or ($isMetadataUpdateProposed -and $hasDataForProposedMetadata)) {
                                        # --- Modification Start: Add detailed verbose logging for filename parts ---
                                        Write-Verbose "  Original Name: '$($fileInfo.Name)'"
                                        Write-Verbose "  Sanitized Name Part: '$sanitizedNamePart'"
                                        Write-Verbose "  Sanitized Location Part: '$sanitizedLocationPart' (UpdateLocation: $($UpdateLocation.IsPresent), ParsedLocation: '$($parsedData.Location)')"
                                        Write-Verbose "  Rating Part: '$ratingPart' (UpdateRating: $($UpdateRating.IsPresent), ParsedRating: '$($parsedData.Rating)')"
                                        Write-Verbose "  New Name Base Parts: $($newNameParts -join ', ')"
                                        Write-Verbose "  New Name Base: '$newNameBase'"
                                        Write-Verbose "  Proposed New Full Name: '$newName'"
                                        # --- Modification End ---
                                        $proposal = [PSCustomObject]@{
                                            OriginalFile      = $fileInfo; NewName           = $newName; NewPath           = $newPath
                                            SanitizedBaseName = $sanitizedNamePart; SpecificTags      = @($parsedData.Tags)
                                            SpecificRating    = $parsedData.Rating; SpecificLocation  = $parsedData.Location
                                            Conflict          = $false; SkipIdentical     = (-not $isRenameProposed) # True if only metadata changes
                                            SpecificDescription = $parsedData.Description
                                        }
                                        if ($isRenameProposed -and (Test-Path -LiteralPath $newPath -PathType Leaf)) { $proposal.Conflict = $true }
                                        [void]$proposedChangesList.Add($proposal); $proposalMade = $true

                                        # Build proposal message
                                        Write-Host "`n--- Proposed Changes for '$($fileInfo.Name)' ---" -ForegroundColor Yellow; $p = $proposal; $renameMsg = if ($p.SkipIdentical) { "'$($p.OriginalFile.Name)' (Metadata only)" } else { "'$($p.OriginalFile.Name)' -> '$($p.NewName)'" }; $titleValueForMeta = if ($p.SanitizedBaseName) { $p.SanitizedBaseName -replace '_', ' ' } else { $originalFileNameBase }; $titleMsg = if ($UpdateTitle.IsPresent -and $p.SanitizedBaseName) { " (Set Title: '$titleValueForMeta')" } else { "" }; $authorMsg = if ($UpdateAuthor.IsPresent -and $AuthorName) { " (Set Author: '$($AuthorName)')" } else { "" }; $subjectMsg = if ($UpdateSubject.IsPresent -and $p.SanitizedBaseName) { " (Set Subject: '$titleValueForMeta')" } else { "" }; $tagsMsg = ""; if ($UpdateTags.IsPresent) { $tagsMsg = if ($p.SpecificTags -ne $null -and $p.SpecificTags.Count -gt 0) { " (Set Tags: $($p.SpecificTags.Count) tags)" } else { " (Clear Tags)" } }; $ratingMsg = if ($UpdateRating.IsPresent -and $p.SpecificRating -ne $null) { " (Set Rating: $($p.SpecificRating))" } else { "" }; $locationMsg = if ($UpdateLocation.IsPresent -and $p.SpecificLocation) { " (Set Location Meta: '$($p.SpecificLocation)')" } else { "" }; $descriptionMsg = if ($UpdateDescription.IsPresent -and $p.SpecificDescription) { " (Set Description: '$($p.SpecificDescription.Substring(0, [System.Math]::Min($p.SpecificDescription.Length, 30)))...')" } else { "" } # Use $p.SpecificDescription
                                        if ($p.Conflict) { Write-Host "[CONFLICT] $renameMsg (Target exists!)" -ForegroundColor Red } else { Write-Host "$renameMsg$titleMsg$authorMsg$subjectMsg$tagsMsg$ratingMsg$locationMsg$descriptionMsg" -ForegroundColor Cyan }; Write-Host "---------------------------------------" -ForegroundColor Yellow

                                        # Confirm or proceed automatically
                                        if ($p.Conflict) { Write-Warning "Modification skipped due to filename conflict."; $proceedWithModify = $false } elseif ($Confirm.IsPresent) { $confirmModifyInput = Read-Host "Proceed with changes for '$($fileInfo.Name)'? (y/N)"; if ($confirmModifyInput -eq 'y') { Write-Verbose "User confirmed."; $proceedWithModify = $true } else { Write-Host "Changes aborted by user." -ForegroundColor Yellow; $proceedWithModify = $false } } else { Write-Host "Proceeding automatically." -ForegroundColor Yellow; $proceedWithModify = $true }
                                    } else { Write-Verbose "No changes proposed (Rename: $isRenameProposed, Metadata: $isMetadataUpdateProposed, HasData: $hasDataForProposedMetadata)." }

                                    # --- Execute Modifications ---
                                    if ($proceedWithModify -and $resolvedExifToolPath) { # Ensure ExifTool is available
                                        $p = $proposedChangesList[0]; $currentFilePath = $p.OriginalFile.FullName; $targetFilePath = $p.NewPath; $renameSuccess = $true; $metadataSuccess = $true

                                        # 1. Rename file if proposed
                                        if ($isRenameProposed) { try { Rename-Item -LiteralPath $currentFilePath -NewName $p.NewName -EA Stop; Write-Host "[Renamed '$($p.OriginalFile.Name)' -> '$($p.NewName)']" -F DarkGray; $currentFilePath = $targetFilePath; $renameSuccess = $true; $processedFileCount++ } catch { $errMsg = "Failed rename '$($p.OriginalFile.FullName)' -> '$($p.NewName)': $($_.Exception.Message)"; Write-Warning $errMsg; [void]$globalRenameErrors.Add($errMsg); $renameSuccess = $false } }

                                        # 2. Update metadata if proposed and rename was successful (or not needed)
                                        if ($renameSuccess -and $isMetadataUpdateProposed -and $hasDataForProposedMetadata) {
                                            try {
                                                Write-Verbose "Updating metadata for '$($p.NewName)' (Path: $currentFilePath)..."
                                                # --- Build ExifTool Arguments ---
                                                $exifArgs = [System.Collections.ArrayList]::new()
                                                $titleValueForMeta = if ($p.SanitizedBaseName) { $p.SanitizedBaseName -replace '_', ' ' } else { $originalFileNameBase }

                                                if ($UpdateTitle.IsPresent -and $p.SanitizedBaseName) { [void]$exifArgs.Add("-Title=""$titleValueForMeta"""); Write-Verbose "  - Adding Title arg." }
                                                if ($UpdateAuthor.IsPresent) {
                                                    Write-Verbose "  - Adding Author (Artist/Creator) args for '$AuthorName'. Writing to multiple fields for compatibility."
                                                    [void]$exifArgs.Add("-Artist=""$AuthorName"""); [void]$exifArgs.Add("-Creator=""$AuthorName""")
                                                }
                                                if ($UpdateRating.IsPresent -and $p.SpecificRating -ne $null) {
                                                    if ($p.SpecificRating -ge 0 -and $p.SpecificRating -le 5) {
                                                        [void]$exifArgs.Add("-Rating=$($p.SpecificRating)"); Write-Verbose "  - Adding Rating arg."
                                                    } else { Write-Warning "  - Invalid rating '$($p.SpecificRating)', ignoring." }
                                                }
                                                if ($UpdateTags.IsPresent) {
                                                    Write-Verbose "  - Adding Keywords/Subject args. Clearing existing tags first."
                                                    [void]$exifArgs.Add("-Keywords=") # Clear existing
                                                    [void]$exifArgs.Add("-Subject=")  # Clear existing
                                                    if ($p.SpecificTags.Count -gt 0) {
                                                        foreach ($tag in $p.SpecificTags) {
                                                            [void]$exifArgs.Add("-Keywords=""$tag""") # Add as individual tags
                                                            [void]$exifArgs.Add("-Subject=""$tag""")  # Add as individual tags
                                                        }
                                                        Write-Verbose "    - Added $($p.SpecificTags.Count) tags."
                                                    } else { Write-Verbose "    - No new tags parsed, ensuring tags are cleared." }
                                                }
                                                # Check UpdateLocation for writing location metadata
                                                if ($UpdateLocation.IsPresent -and $p.SpecificLocation) {
                                                    $locationParts = $p.SpecificLocation -split ',' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                                                    if ($locationParts.Count -gt 0) {
                                                        $city = $locationParts[0]
                                                        $state = if ($locationParts.Count -gt 1) { $locationParts[1] } else { $null }
                                                        $country = if ($locationParts.Count -gt 2) { $locationParts[2] } else { $null }
                                                        if ($city) { [void]$exifArgs.Add("-City=""$city"""); Write-Verbose "  - Adding City arg." }
                                                        if ($state) { [void]$exifArgs.Add("-State=""$state"""); Write-Verbose "  - Adding State arg." }
                                                        if ($country) { [void]$exifArgs.Add("-Country=""$country"""); Write-Verbose "  - Adding Country arg." }
                                                        # Also add to Comment if not updating Subject/Description
                                                        if (-not $UpdateSubject.IsPresent -and -not $UpdateDescription.IsPresent) { [void]$exifArgs.Add("-Comment=""$($p.SpecificLocation)"""); Write-Verbose "  - Adding Location to Comment arg (fallback)." }
                                                    } else { Write-Warning "  - Could not parse City/State/Country from Location: '$($p.SpecificLocation)'"}
                                                }
                                                if ($UpdateDescription.IsPresent -and $p.SpecificDescription) {
                                                    [void]$exifArgs.Add("-Description=""$($p.SpecificDescription)"""); Write-Verbose "  - Adding Description arg."
                                                    # Overwrite Comment with Description if Description is active
                                                    [void]$exifArgs.Add("-Comment=""$($p.SpecificDescription)"""); Write-Verbose "  - Adding Description to Comment arg."
                                                }
                                                elseif ($UpdateSubject.IsPresent -and $p.SanitizedBaseName) { # Only update Comment with Title if Description is NOT active
                                                    [void]$exifArgs.Add("-Comment=""$titleValueForMeta"""); Write-Verbose "  - Adding Title to Comment arg (Subject)."
                                                }

                                                # --- Execute ExifTool ---
                                                if ($exifArgs.Count -gt 0) {
                                                    [void]$exifArgs.Add("-overwrite_original") # Modify file in place
                                                    [void]$exifArgs.Add("-m") # Ignore minor errors
                                                    [void]$exifArgs.Add($currentFilePath) # Use current path (might have been renamed)
                                                    Write-Verbose "  Executing ExifTool with $($exifArgs.Count - 2) tag arguments..."
                                                    $exifCmd = "& `"$resolvedExifToolPath`" $($exifArgs -join ' ')"
                                                    Write-Verbose "  Command: $exifCmd"
                                                    $exifResult = & $resolvedExifToolPath @exifArgs 2>&1 # Capture stdout and stderr
                                                    Write-Verbose "  ExifTool Update Output: $($exifResult -join "`n  ")"
                                                    # Check exit code and success message
                                                    if ($LASTEXITCODE -eq 0 -and ($exifResult -match '1 (image|video|audio|document|file) files? updated')) { # More robust check
                                                        Write-Host "[Metadata Updated for '$($p.NewName)']" -ForegroundColor DarkGreen
                                                        if (-not $isRenameProposed) { $processedFileCount++ } # Count as processed only if metadata was the only change
                                                    } else {
                                                        throw "ExifTool execution failed or did not report success. ExitCode: $LASTEXITCODE. Output: $($exifResult -join '; ')"
                                                    }
                                                } else { Write-Host "[Metadata Unchanged for '$($p.NewName)'] (No relevant data parsed or flags enabled)" -ForegroundColor DarkGray }

                                            } catch {
                                                $errMsg = "Failed metadata update for '$($p.NewName)': $($_.Exception.Message) (Check file permissions, if file is open elsewhere, or if it's read-only)." # Enhanced error message
                                                Write-Warning $errMsg; [void]$globalMetadataErrors.Add($errMsg); $metadataSuccess = $false
                                                if (-not $isRenameProposed) { $skippedFileCount++ } # Increment skipped only if rename didn't happen/fail
                                            }
                                        } elseif ($renameSuccess -and (-not $isMetadataUpdateProposed -or -not $hasDataForProposedMetadata)) {
                                             Write-Verbose "Metadata update skipped for '$($p.NewName)' (Not requested or no data parsed)."
                                        }
                                    } # End if ($proceedWithModify)
                                } # End if ($ModifyFiles.IsPresent)

                                # --- Save Parsed Results to CSV if requested ---
                                if ($PSBoundParameters.ContainsKey('ResultsCsvFile') -and -not ([string]::IsNullOrWhiteSpace($ResultsCsvFile))) {
                                    Save-ParsedResultsToCsv -OriginalFileInfo $fileInfo -ParsedData $parsedData -ResultsCsvFilePath $ResultsCsvFile
                                }

                            } else { # API Call Failed
                                Write-Error "API call failed for File $fileIndex`: $($fileInfo.Name)."
                                if ($apiResult -ne $null) {
                                    if ($apiResult.StatusCode) { Write-Error "  Status: $($apiResult.StatusCode)" }
                                    if ($apiResult.ResponseBody) { Write-Error "  Body: $($apiResult.ResponseBody)" }
                                    if ($apiResult.ErrorRecord) { Write-Error "  Details: $($apiResult.ErrorRecord.Exception.Message)" }
                                } else { Write-Error "  Invoke-GeminiApi returned null." }
                                if ($PSBoundParameters.ContainsKey('OutputFile')) {
                                    try {
                                        $statusCodeInfo = if($apiResult){"Status: $($apiResult.StatusCode)"}else{"N/A"}
                                        $exceptionInfo = if($apiResult -and $apiResult.ErrorRecord){"Exception: $($apiResult.ErrorRecord.Exception.Message)"}else{"N/A"}
                                        $responseBodyInfo = if($apiResult){"Body:`n$($apiResult.ResponseBody)"}else{"Body: N/A"}
                                        $errorContent="`n--- File '$($fileInfo.Name)' ($(Get-Date)) - API ERROR ---`nPROMPT:`n$($invokeParams.Prompt)`n`nGemini ERROR:`n$statusCodeInfo`n$exceptionInfo`n$responseBodyInfo`n--- End Error ---`n"
                                        $errorContent|Out-File -FilePath $OutputFile -Append -Encoding UTF8 -EA Stop
                                        Write-Verbose "Appended API error to log."
                                    } catch { Write-Warning "Failed append API error to '$OutputFile': $($_.Exception.Message)" }
                                }
                                $skippedFileCount++ # Increment skipped count on API failure
                            }

                            # Delay between files if specified
                            if ($FileDelaySec -gt 0 -and $fileIndex -lt $discoveredFiles.Count) { Write-Verbose "Pausing for $FileDelaySec second(s)..."; Start-Sleep -Seconds $FileDelaySec }

                        } # End foreach ($fileInfo in $discoveredFiles)

                        # Complete Progress Bar
                        Write-Progress -Activity "Processing Media Files" -Completed

                        # Summary message after processing all files
                        Write-Host "`n--- Finished Processing Initial Files ($processedFileCount files modified, $skippedFileCount files skipped) ---" -ForegroundColor Yellow
                        Write-Host "------------------------------------------" -ForegroundColor Cyan
                        $isFirstTurn = $false # Mark first turn done *after* file processing
                        # After processing files, loop continues to prompt for the *next* turn's input
                        continue # Go to the start of the while loop to prompt for the next turn
                    }
                    # If file processing didn't happen (no files found or no -MediaFolder), proceed to prompt
                    # but don't 'continue' as we need input for this turn.
                    Write-Verbose "Initial file processing skipped or completed without files."
                }
                elseif ($processGooglePhotos) {
                    # --- Process GOOGLE PHOTOS Items ---
                    Write-Host "`nProcessing GOOGLE PHOTOS items using StartPrompt..." -ForegroundColor Yellow
                    $accessToken = Get-GooglePhotosAccessToken
                    if (-not $accessToken) {
                        Write-Error "Cannot proceed with Google Photos without access token."
                        # Decide how to handle - maybe exit or just skip to interactive?
                        # For now, skip to interactive
                    } else {
                        $mediaItems = $null
                        if ($PSBoundParameters.ContainsKey('GooglePhotosAlbumId')) {
                            $mediaItems = Get-GooglePhotosMediaItems -AccessToken $accessToken -AlbumId $GooglePhotosAlbumId
                        } elseif ($PSBoundParameters.ContainsKey('GooglePhotosSearchFilter')) {
                            $mediaItems = Get-GooglePhotosMediaItems -AccessToken $accessToken -SearchFilter $GooglePhotosSearchFilter
                        }

                        if ($null -eq $mediaItems) { Write-Warning "Failed to retrieve media items from Google Photos." }
                        elseif ($mediaItems.Count -eq 0) { Write-Warning "No media items found matching the criteria in Google Photos." }
                        else {
                            $itemIndex = 0
                            $tempDir = Join-Path -Path $env:TEMP -ChildPath "GeminiPhotosTemp"
                            New-Item -Path $tempDir -ItemType Directory -Force | Out-Null # Ensure temp dir exists

                            foreach ($item in $mediaItems) {
                                $itemIndex++
                                Write-Host "`nProcessing Google Photos Item $itemIndex of $($mediaItems.Count): $($item.filename) (ID: $($item.id))" -ForegroundColor Cyan

                                # --- Download Item Temporarily ---
                                $tempFilePath = $null
                                if ($item.baseUrl) {
                                    # Append download parameter based on type (heuristic)
                                    $downloadUrl = if ($item.mediaMetadata.video) { "$($item.baseUrl)=dv" } else { "$($item.baseUrl)=d" }
                                    $tempFileName = Sanitize-Filename -InputString "$($item.id)_$($item.filename)" -MaxLength 150 # Create a unique-ish temp name
                                    $tempFilePath = Join-Path -Path $tempDir -ChildPath $tempFileName
                                    try {
                                        Write-Verbose "  Downloading '$($item.filename)' temporarily to '$tempFilePath'..."
                                        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFilePath -TimeoutSec 180 -ErrorAction Stop # Add timeout
                                        Write-Verbose "  Download complete."
                                    } catch {
                                        Write-Warning "  Failed to download Google Photos item '$($item.filename)': $($_.Exception.Message)"
                                        $tempFilePath = $null # Ensure path is null on failure
                                    }
                                } else { Write-Warning "  Media item '$($item.filename)' has no baseUrl. Skipping." }

                                if ($tempFilePath) {
                                    # --- API Call for this item (using temp file) ---
                                    $invokeParams = @{ ApiKey = $ApiKey; Model = $sessionConfig.Model; TimeoutSec = $TimeoutSec; MaxRetries = $MaxRetries; InitialRetryDelaySec = $InitialRetryDelaySec; Prompt = $basePrompt; InlineFilePaths = @($tempFilePath); ConversationHistory= @() }; if ($PSBoundParameters.ContainsKey('GenerationConfig')) { $invokeParams.GenerationConfig = $GenerationConfig }
                                    Write-Host "[DEBUG] Sending Prompt to Gemini (GP Item: $($item.filename)):`n$($invokeParams.Prompt)" -ForegroundColor DarkYellow; Write-Host "Gemini is thinking..." -ForegroundColor DarkGray
                                    $timerJob = Start-Job -ScriptBlock { Start-Sleep -Seconds 3600 }; try { $apiResult = Invoke-GeminiApi @invokeParams } finally { Stop-Job -Job $timerJob -EA SilentlyContinue; Remove-Job -Job $timerJob -Force -EA SilentlyContinue; Write-Host "`r".PadRight([Console]::WindowWidth - 1); Write-Host "`r" -NoNewline }

                                    # --- Process Result ---
                                    if ($apiResult -ne $null -and $apiResult.Success) {
                                        Write-Host "Gemini Response (GP Item: $($item.filename)):" -ForegroundColor Green; Write-Host $apiResult.GeneratedText -ForegroundColor Green
                                        # Log, Parse, etc. (similar to local file)
                                        # ...

                                        # --- Modification (Description Only) ---
                                        if ($ModifyFiles.IsPresent) { # Reuse ModifyFiles flag intent
                                            $parsedData = Parse-GeminiResponse -GeminiText $apiResult.GeneratedText
                                            if ($parsedData.Description) {
                                                # Call Update-GooglePhotosDescription (Needs PSCmdlet for ShouldProcess)
                                                $updateSuccess = Update-GooglePhotosDescription -AccessToken $accessToken -MediaItemId $item.id -NewDescription $parsedData.Description -PSCmdlet $PSCmdlet
                                                if ($updateSuccess) { $processedFileCount++ } else { $skippedFileCount++ }
                                            } else { Write-Verbose "  No description parsed from Gemini response. Skipping Google Photos update." }
                                        }
                                    } else { # API Call Failed
                                        Write-Error "API call failed for Google Photos Item $itemIndex`: $($item.filename)."
                                        # Log error (similar to local file)
                                        # ...
                                        $skippedFileCount++
                                    }

                                    # --- Clean up temporary file ---
                                    Remove-Item -LiteralPath $tempFilePath -Force -ErrorAction SilentlyContinue
                                    Write-Verbose "  Removed temporary file '$tempFilePath'."

                                    # --- Delay ---
                                    if ($FileDelaySec -gt 0 -and $itemIndex -lt $mediaItems.Count) { Write-Verbose "Pausing for $FileDelaySec second(s)..."; Start-Sleep -Seconds $FileDelaySec }
                                } else { $skippedFileCount++ } # Skip if download failed
                            } # End foreach item

                            # Clean up temp directory if empty? Optional.
                            # Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

                            Write-Progress -Activity "Processing Google Photos Items" -Completed
                            Write-Host "`n--- Finished Processing Google Photos Items ($processedFileCount descriptions updated, $skippedFileCount items skipped/failed) ---" -ForegroundColor Yellow
                        } # End if items found
                    } # End if access token obtained
                    Write-Host "------------------------------------------" -ForegroundColor Cyan
                    $isFirstTurn = $false # Mark first turn done
                    continue # Go to start of loop for interactive prompt
                } # End elseif ($processGooglePhotos)

                # --- Handle First Turn Input (if not handled by file processing 'continue') ---
                if ($PSBoundParameters.ContainsKey('StartPrompt') -and -not $PSBoundParameters.ContainsKey('MediaFolder')) {
                    # StartPrompt provided without MediaFolder
                    $currentPromptInput = $StartPrompt
                    Write-Host "`nYou (Start): $currentPromptInput" -ForegroundColor White
                    # Proceed directly to API call section below
                } else {
                    # No initial files processed AND no StartPrompt without MediaFolder
                    # This is the fully interactive start case.
                    Write-Host "" # Attempt to force a newline/flush before debug/commands
                    # Display commands first, then the prompt instruction
                    Write-Host "[DEBUG] Reached interactive first prompt section." -ForegroundColor Magenta # ADDED DEBUG LINE
                    # --- Updated Command List with Descriptions ---
                    Write-Host "Commands:" -ForegroundColor Cyan
                    Write-Host "  /history      - Display conversation history." -ForegroundColor Cyan
                    Write-Host "  /clear        - Clear conversation history." -ForegroundColor Cyan
                    Write-Host "  /retry        - Retry the last failed API call." -ForegroundColor Cyan
                    Write-Host "  /config       - Show current session settings." -ForegroundColor Cyan
                    Write-Host "  /save         - Save history to CSV (if -CsvOutputFile specified)." -ForegroundColor Cyan
                    Write-Host "  /media [path] - Add media (folder/file) for the next prompt. If no path, prompts interactively." -ForegroundColor Cyan
                    Write-Host "  /generate ... - Generate an image via Vertex AI." -ForegroundColor Cyan
                    Write-Host "  /generate_from <path> - Use Gemini to describe image at <path>, then generate a new image." -ForegroundColor Cyan # Added /generate_from
                    Write-Host "  /model <name> - Change the Gemini model (e.g., /model gemini-1.5-pro-latest)." -ForegroundColor Cyan # Added /model
                    # --- NEW Google Photos Commands ---
                    Write-Host "  /gp_albums    - List Google Photos albums." -ForegroundColor Cyan
                    Write-Host "  /gp_media <albumId> - List media items in a Google Photos album." -ForegroundColor Cyan
                    Write-Host "  /gp_process <mediaItemId> - Process a single Google Photos item using the last prompt." -ForegroundColor Cyan
                    # --- End NEW Google Photos Commands ---
                    Write-Host "  /exit         - Exit the chat session." -ForegroundColor Cyan
                    Write-Host "Enter your first prompt:" -ForegroundColor Cyan
                    try { $currentPromptInput = Read-Host "`nYou" } catch { Write-Warning "Input error. Exiting."; break }
                    if ($currentPromptInput.Trim().ToLowerInvariant() -eq '/exit') { Write-Host "Exiting." -ForegroundColor Cyan; break }
                    # Proceed to command handling / API call section below
                }
                $isFirstTurn = $false # Mark first turn done *after* handling input/prompt

            } else {
                # --- Subsequent Turns ---
                # Get Text Input
                try { $currentPromptInput = Read-Host "`nYou"; if ([string]::IsNullOrWhiteSpace($currentPromptInput)) { Write-Host "Enter a prompt or '/exit'." -ForegroundColor Yellow; continue } } catch { Write-Warning "Input error. Exiting."; break }
                if ($currentPromptInput.Trim().ToLowerInvariant() -eq '/exit') { Write-Host "Exiting." -ForegroundColor Cyan; break }
            }

            # --- Handle Commands (Applies to first interactive turn AND subsequent turns) ---
            $trimmedInput = $currentPromptInput.Trim()
            $commandExecuted = $false # Renamed from skipApiCall for clarity in this section
            $mediaAddedThisTurn = $false # Flag to track if /media was used

            # --- Helper Function for Media Input (used by /media) ---
            function Prompt-ForMediaInput {
                param([ref]$ImageFolderRef, [ref]$VideoFolderRef, [ref]$RecurseRef, [ref]$InlineFilePathsRef)
                $rawMediaInput = Read-Host "Enter Media Folder Path or File Path"
                if (-not [string]::IsNullOrWhiteSpace($rawMediaInput)) {
                    $mediaInput = $rawMediaInput.Trim('"').Trim("'")
                    if (Test-Path -LiteralPath $mediaInput -PathType Container) {
                        $ImageFolderRef.Value = $mediaInput; $VideoFolderRef.Value = $mediaInput
                        Write-Host "(Will search folder: '$mediaInput')" -ForegroundColor Gray
                        $recurseMedia = Read-Host "Search recursively? (y/N)"; if ($recurseMedia.Trim().ToLowerInvariant() -eq 'y') { $RecurseRef.Value = $true }
                    } elseif (Test-Path -LiteralPath $mediaInput -PathType Leaf) {
                        $InlineFilePathsRef.Value = @($mediaInput); Write-Host "(Will use file: $mediaInput)" -ForegroundColor Gray
                    } else { Write-Warning "Media path not found or invalid: $mediaInput" }
                }
            }

            if ($trimmedInput.StartsWith('/')) {
                switch -Regex ($trimmedInput) {
                    '^/(history|hist)$' {
                        Write-Host "`n--- Conversation History ---" -ForegroundColor Yellow
                        if ($conversationHistory.Count -eq 0) { Write-Host "(History is empty)" -ForegroundColor Gray }
                        else {
                            $turnIndex = 1
                            for ($i = 0; $i -lt $conversationHistory.Count; $i++) {
                                $turn = $conversationHistory[$i]
                                $role = $turn.role.ToUpper()
                                $text = $turn.parts | Where-Object { $_.text } | Select-Object -ExpandProperty text
                                $mediaCount = ($turn.parts | Where-Object { $_.inline_data -or $_.file_data }).Count # Check both inline and file data
                                Write-Host "[$($role)] $($text)" -ForegroundColor (if ($role -eq 'USER') { [ConsoleColor]::White } else { [ConsoleColor]::Green })
                                if ($mediaCount -gt 0) { Write-Host "  ($mediaCount media part(s) included)" -ForegroundColor Gray }
                            }
                        }
                        Write-Host "--------------------------" -ForegroundColor Yellow
                        $commandExecuted = $true
                    }
                    '^/clear$' {
                        Write-Host "`nClearing conversation history." -ForegroundColor Yellow
                        $conversationHistory = @()
                        $lastUserPrompt = $null # Clear last prompt for retry
                        $lastApiResult = $null # Clear last result
                        $commandExecuted = $true
                    }
                    '^/retry$' {
                        if ($lastApiResult -ne $null -and -not $lastApiResult.Success) {
                            Write-Host "`nRetrying last failed API call..." -ForegroundColor Yellow
                            $currentPromptInput = $lastUserPrompt # Restore the last prompt
                            # Note: This simple retry doesn't restore media context from the failed turn.
                            # It will use the restored $currentPromptInput in the normal API call flow below.
                            Write-Host "Retrying prompt: $currentPromptInput" -ForegroundColor Gray
                            # Let the loop proceed to the API call section
                        } else {
                            Write-Warning "No failed API call to retry, or last call was successful."
                            $commandExecuted = $true # Prevent API call for this '/retry' input
                        }
                    }
                    '^/config$' {
                        Write-Host "`n--- Session Configuration ---" -ForegroundColor Yellow
                        $sessionConfig.GetEnumerator() | Sort-Object Name | ForEach-Object { Write-Host ("{0,-25}: {1}" -f $_.Name, ($_.Value | Out-String -Stream).Trim()) }
                        Write-Host "---------------------------" -ForegroundColor Yellow
                        $commandExecuted = $true
                    }
                    '^/save$' {
                        Write-Host "`nAttempting to save conversation history..." -ForegroundColor Yellow
                        # Check if CsvOutputFile is specified AND history is not empty
                        if ($sessionConfig.CsvOutputFile -and $conversationHistory.Count -gt 0) {
                            Save-ChatToCsv -ConversationHistory $conversationHistory -CsvOutputFile $sessionConfig.CsvOutputFile
                        } elseif (-not $sessionConfig.CsvOutputFile) {
                            Write-Warning "Cannot save: No -CsvOutputFile was specified when starting the script."
                        } else { # Implies CsvOutputFile exists, but history is empty
                            Write-Warning "Cannot save: Conversation history is empty."
                        }
                        $commandExecuted = $true
                    }
                    '^/media(\s+(.+))?$' { # Updated regex to capture optional path
                        # Clear any previous media selections from this turn attempt
                        $currentImageFolder = $null; $currentVideoFolder = $null; $currentRecurse = $false; $currentInlineFilePaths = $null

                        if ($Matches[2]) { # Path was provided directly with the command
                            $mediaPathInput = $Matches[2].Trim().Trim('"').Trim("'") # Get the path from capture group 2
                            Write-Host "`nProcessing media path from command: '$mediaPathInput'" -ForegroundColor Yellow
                            if (Test-Path -LiteralPath $mediaPathInput -PathType Container) {
                                $currentImageFolder = $mediaPathInput; $currentVideoFolder = $mediaPathInput
                                Write-Host "(Will search folder: '$mediaPathInput')" -ForegroundColor Gray
                                $recurseMedia = Read-Host "Search recursively? (y/N)"; if ($recurseMedia.Trim().ToLowerInvariant() -eq 'y') { $currentRecurse = $true }
                            } elseif (Test-Path -LiteralPath $mediaPathInput -PathType Leaf) {
                                $currentInlineFilePaths = @($mediaPathInput); Write-Host "(Will use file: $mediaPathInput)" -ForegroundColor Gray
                            } else {
                                Write-Warning "Media path provided with /media command not found or invalid: '$mediaPathInput'"
                            }
                        } else { # No path provided, use interactive prompt
                            Write-Host "`nAdding media for the next prompt..." -ForegroundColor Yellow
                            # Call the helper to get media input and update the turn variables
                            Prompt-ForMediaInput -ImageFolderRef ([ref]$currentImageFolder) -VideoFolderRef ([ref]$currentVideoFolder) -RecurseRef ([ref]$currentRecurse) -InlineFilePathsRef ([ref]$currentInlineFilePaths)
                        }

                        if ($currentImageFolder -or $currentVideoFolder -or $currentInlineFilePaths) {
                            # Media was added, now prompt for the text part immediately
                            try { $currentPromptInput = Read-Host " You (prompt for media)" } catch { Write-Warning "Input error. Exiting."; break }
                            # Let the loop proceed to the API call section below
                        } else {
                            $commandExecuted = $true
                        }
                    }
                    '^/model(\s+(\S+))?$' { # Updated regex to make the model name optional
                        if ($Matches[2]) { # Check if the second capture group (model name) exists
                            $newModel = $Matches[2].Trim()
                            # Display current model before changing
                            Write-Host "`nCurrent model: '$($sessionConfig.Model)'" -ForegroundColor Gray
                            Write-Host "Changing model to '$newModel'..." -ForegroundColor Yellow
                            $sessionConfig.Model = $newModel # Update the model in the session state
                            Write-Host "Model updated for subsequent API calls." -ForegroundColor Green
                        } else {
                            # Only /model was typed, display the current model
                            Write-Host "`nCurrent model: '$($sessionConfig.Model)'" -ForegroundColor Cyan
                        }
                        $commandExecuted = $true
                    }
                    '^/generate_from\s+(.+)' {
                        $inputPath = $Matches[1].Trim().Trim('"').Trim("'")
                        $sourceImagePaths = [System.Collections.ArrayList]::new()
                        $sourcePathType = $null

                        # 1. Validate input path and get image file(s)
                        if (Test-Path -LiteralPath $inputPath -PathType Leaf) {
                            $sourceImagePath = $inputPath
                            $sourcePathType = 'File'
                            Write-Host "`n--- Generate From Image File: '$sourceImagePath' ---" -ForegroundColor Yellow
                        } elseif (Test-Path -LiteralPath $inputPath -PathType Container) {
                            Write-Host "`n--- Generate From Image in Folder: '$inputPath' ---" -ForegroundColor Yellow
                            # Find the first valid image file in the folder (non-recursive)
                            $imageExtensions = @('.jpg', '.jpeg', '.png', '.webp', '.gif', '.heic', '.heif', '.bmp', '.tif', '.tiff')
                            $foundImages = Get-ChildItem -LiteralPath $inputPath -File | Where-Object { $imageExtensions -contains $_.Extension.ToLowerInvariant() }
                            if ($foundImages.Count -gt 0) {
                                $foundImages | ForEach-Object { [void]$sourceImagePaths.Add($_.FullName) }
                                Write-Host "  Found $($sourceImagePaths.Count) image(s) to process." -ForegroundColor Gray
                                $sourcePathType = 'Folder'
                            } else { Write-Error "No supported image files found directly within folder '$inputPath'." }
                        } else {
                            Write-Error "Path not found or invalid: '$inputPath'"
                        }
                        # If it was a single file path, add it to the list for consistent looping
                        if ($sourcePathType -eq 'File' -and $sourceImagePath) {
                            [void]$sourceImagePaths.Add($sourceImagePath)
                        }

                        if ($sourceImagePaths.Count -eq 0) {
                            $commandExecuted = $true; continue
                        }

                        # --- Loop through each found image path ---
                        $imageIndex = 0
                        foreach ($currentImagePath in $sourceImagePaths) {
                            $imageIndex++
                            Write-Host "`nProcessing image $imageIndex of $($sourceImagePaths.Count): '$currentImagePath'" -ForegroundColor Cyan

                            # 2. Call Gemini to describe the current image
                            $descriptionPrompt = "Describe this image in vivid detail, focusing on elements, style, and mood, suitable for generating a similar image with an AI image generator."
                            Write-Host "Asking Gemini to describe the image..." -ForegroundColor DarkGray
                            $descInvokeParams = @{
                                ApiKey          = $ApiKey
                                Model           = $sessionConfig.Model # Use current session model
                                Prompt          = $descriptionPrompt
                                InlineFilePaths = @($currentImagePath) # Pass the CURRENT image path
                                ConversationHistory = @() # Use empty history for this specific task
                                TimeoutSec      = $sessionConfig.TimeoutSec
                                MaxRetries      = $sessionConfig.MaxRetries
                                InitialRetryDelaySec = $sessionConfig.InitialRetryDelaySec
                            }
                            if ($sessionConfig.GenerationConfig) { $descInvokeParams.GenerationConfig = $sessionConfig.GenerationConfig }

                            $descriptionResult = Invoke-GeminiApi @descInvokeParams

                            if (-not $descriptionResult.Success) {
                                Write-Error "Failed to get description from Gemini for '$currentImagePath'."
                                # Error details are usually printed by Invoke-GeminiApi
                                continue # Skip to the next image on description failure
                            }

                            $generatedDescription = $descriptionResult.GeneratedText
                            Write-Host "Gemini Description:" -ForegroundColor Green
                            Write-Host $generatedDescription -ForegroundColor Green

                            # 3. Call Vertex AI with the generated description
                            Write-Host "`nProceeding to generate image based on description..." -ForegroundColor Yellow

                            # --- Directly call generation logic ---
                            if (-not $sessionConfig.VertexProjectId -or -not $sessionConfig.VertexLocationId -or -not $sessionConfig.VertexDefaultOutputFolder) {
                                Write-Error "Cannot generate image. Vertex AI parameters (ProjectId, LocationId, DefaultOutputFolder) not fully configured in session state."
                                continue # Skip to next image if Vertex config is bad
                            }
                            if (-not (Test-Path -LiteralPath $sessionConfig.VertexDefaultOutputFolder -PathType Container)) {
                                Write-Warning "Default output folder '$($sessionConfig.VertexDefaultOutputFolder)' does not exist. Attempting to create..."
                                try { New-Item -Path $sessionConfig.VertexDefaultOutputFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null; Write-Verbose "Created default output folder." }
                                catch { Write-Error "Failed to create default output folder '$($sessionConfig.VertexDefaultOutputFolder)'. Cannot generate image. Error: $($_.Exception.Message)"; continue } # Skip to next image
                            }
                            $vertexParams = @{
                                ProjectId    = $sessionConfig.VertexProjectId
                                LocationId   = $sessionConfig.VertexLocationId
                                Prompt       = $generatedDescription # Use the description from Gemini
                                OutputFolder = $sessionConfig.VertexDefaultOutputFolder
                            }
                            if ($sessionConfig.Verbose) { $vertexParams.Verbose = $true }
                            Start-VertexImageGeneration @vertexParams # This function handles its own errors/output
                            # --- End direct call ---

                            # Add delay between processing each image in the folder if specified
                            if ($sessionConfig.FileDelaySec -gt 0 -and $imageIndex -lt $sourceImagePaths.Count) {
                                Write-Verbose "Pausing for $($sessionConfig.FileDelaySec) second(s) before next image..."
                                Start-Sleep -Seconds $sessionConfig.FileDelaySec
                            }
                        } # --- End foreach loop ---
                        $commandExecuted = $true # Prevent standard chat API call
                    }
                    # --- NEW Google Photos Commands ---
                    '^/gp_albums$' {
                        Write-Host "`nListing Google Photos Albums..." -ForegroundColor Yellow
                        $accessToken = Get-GooglePhotosAccessToken
                        if (-not $accessToken) { Write-Error "Cannot list albums without access token. Ensure 'gcloud' is authenticated." }
                        else {
                            $albums = Get-GooglePhotosAlbums -AccessToken $accessToken
                            if ($albums) {
                                if ($albums.Count -eq 0) { Write-Host "No albums found." -ForegroundColor Gray }
                                else {
                                    $albums | Format-Table -Property @{Name='Title';Expression={$_.title}}, @{Name='ID';Expression={$_.id}}, @{Name='Items';Expression={$_.mediaItemsCount}}
                                }
                            } # Else: Error message already shown by Get-GooglePhotosAlbums
                        }
                        $commandExecuted = $true
                    }
                    '^/gp_media\s+(\S+)' {
                        $albumId = $Matches[1].Trim()
                        Write-Host "`nListing Media Items in Google Photos Album ID: $albumId..." -ForegroundColor Yellow
                        $accessToken = Get-GooglePhotosAccessToken
                        if (-not $accessToken) { Write-Error "Cannot list media without access token. Ensure 'gcloud' is authenticated." }
                        else {
                            $mediaItems = Get-GooglePhotosMediaItems -AccessToken $accessToken -AlbumId $albumId
                            if ($mediaItems) {
                                if ($mediaItems.Count -eq 0) { Write-Host "No media items found in album '$albumId'." -ForegroundColor Gray }
                                else {
                                     Write-Host "Found $($mediaItems.Count) items:"
                                     $mediaItems | Format-Table -Property @{Name='Filename';Expression={$_.filename}}, @{Name='ID';Expression={$_.id}}, @{Name='Type';Expression={$_.mimeType}}, @{Name='Created';Expression={$_.mediaMetadata.creationTime}}
                                }
                            } # Else: Error message already shown by Get-GooglePhotosMediaItems
                        }
                        $commandExecuted = $true
                    }
                    '^/gp_process\s+(\S+)' {
                        $mediaItemId = $Matches[1].Trim()
                        Write-Host "`nProcessing Google Photos Item ID: $mediaItemId..." -ForegroundColor Yellow

                        # Determine prompt (use last successful user prompt or a default)
                        $promptToUse = $lastUserPrompt # Use the last text prompt entered by the user
                        if ([string]::IsNullOrWhiteSpace($promptToUse)) {
                            $promptToUse = "Describe this media item." # Default prompt
                            Write-Warning "No previous user prompt found, using default: '$promptToUse'"
                        }
                        Write-Host "Using prompt: $promptToUse" -ForegroundColor Gray

                        $accessToken = Get-GooglePhotosAccessToken
                        if (-not $accessToken) { Write-Error "Cannot process item without access token. Ensure 'gcloud' is authenticated." }
                        else {
                            # 1. Get Media Item Details
                            $item = Get-GooglePhotosMediaItemById -AccessToken $accessToken -MediaItemId $mediaItemId
                            if (-not $item) { Write-Error "Failed to get details for media item '$mediaItemId'." }
                            else {
                                # 2. Download Temporarily
                                $tempFilePath = $null; $tempDir = Join-Path -Path $env:TEMP -ChildPath "GeminiPhotosTemp"
                                New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
                                if ($item.baseUrl) {
                                    $downloadUrl = if ($item.mediaMetadata.video) { "$($item.baseUrl)=dv" } else { "$($item.baseUrl)=d" }
                                    $tempFileName = Sanitize-Filename -InputString "$($item.id)_$($item.filename)" -MaxLength 150
                                    $tempFilePath = Join-Path -Path $tempDir -ChildPath $tempFileName
                                    try { Write-Verbose "  Downloading '$($item.filename)' temporarily..."; Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFilePath -TimeoutSec 180 -EA Stop; Write-Verbose "  Download complete." }
                                    catch { Write-Warning "  Failed to download '$($item.filename)': $($_.Exception.Message)"; $tempFilePath = $null }
                                } else { Write-Warning "  Media item '$($item.filename)' has no baseUrl. Cannot download." }

                                if ($tempFilePath) {
                                    # 3. Call Gemini API
                                    $invokeParams = @{ ApiKey = $ApiKey; Model = $sessionConfig.Model; TimeoutSec = $sessionConfig.TimeoutSec; MaxRetries = $sessionConfig.MaxRetries; InitialRetryDelaySec = $sessionConfig.InitialRetryDelaySec; Prompt = $promptToUse; InlineFilePaths = @($tempFilePath); ConversationHistory = $conversationHistory }; if ($sessionConfig.GenerationConfig) { $invokeParams.GenerationConfig = $sessionConfig.GenerationConfig }
                                    Write-Host "Gemini is thinking..." -ForegroundColor DarkGray
                                    $timerJob = Start-Job -ScriptBlock { Start-Sleep -Seconds 3600 }; try { $apiResult = Invoke-GeminiApi @invokeParams } finally { Stop-Job -Job $timerJob -EA SilentlyContinue; Remove-Job -Job $timerJob -Force -EA SilentlyContinue; Write-Host "`r".PadRight([Console]::WindowWidth - 1); Write-Host "`r" -NoNewline }

                                    # 4. Process Result
                                    if ($apiResult -ne $null -and $apiResult.Success) {
                                        Write-Host "`nGemini Response (Item: $($item.filename)):" -ForegroundColor Green; Write-Host $apiResult.GeneratedText -ForegroundColor Green
                                        $conversationHistory = $apiResult.UpdatedConversationHistory # Update history
                                        # 5. Attempt Description Update if ModifyFiles is enabled
                                        if ($sessionConfig.ModifyFiles) {
                                            $parsedData = Parse-GeminiResponse -GeminiText $apiResult.GeneratedText
                                            if ($parsedData.Description) {
                                                Update-GooglePhotosDescription -AccessToken $accessToken -MediaItemId $item.id -NewDescription $parsedData.Description -PSCmdlet $PSCmdlet # Pass PSCmdlet
                                            } else { Write-Verbose "  No description parsed from Gemini response. Skipping Google Photos update." }
                                        }
                                    } else { Write-Error "API call failed for item '$($item.filename)'." } # Error details printed by Invoke-GeminiApi

                                    # 6. Clean up temp file
                                    Remove-Item -LiteralPath $tempFilePath -Force -ErrorAction SilentlyContinue; Write-Verbose "  Removed temporary file."
                                } # End if ($tempFilePath)
                            } # End else (item found)
                        } # End else (accessToken found)
                        $commandExecuted = $true
                    }
                    # --- End NEW Google Photos Commands ---
                }
            }

            # --- Check for Image Generation Command ---
            # Allow command anywhere on the line, capture the rest
            if (-not $commandExecuted -and $trimmedInput -match '/(generate|image)\s+(.+)') {
                $imageGenPrompt = $Matches[2].Trim()
                Write-Host "Image Generation command detected: /generate" -ForegroundColor Magenta
                Write-Host "Prompt: $imageGenPrompt" -ForegroundColor Magenta

                # Validate Vertex AI parameters are set
                if (-not $PSBoundParameters.ContainsKey('VertexProjectId') -or -not $PSBoundParameters.ContainsKey('VertexLocationId') -or -not $PSBoundParameters.ContainsKey('VertexDefaultOutputFolder')) {
                    Write-Error "Cannot generate image. Please start the script with -VertexProjectId, -VertexLocationId, and -VertexDefaultOutputFolder parameters."
                    continue # Skip to next loop iteration
                }
                if (-not (Test-Path -LiteralPath $VertexDefaultOutputFolder -PathType Container)) {
                     Write-Warning "Default output folder '$VertexDefaultOutputFolder' does not exist. Attempting to create..."
                     try { New-Item -Path $VertexDefaultOutputFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null; Write-Verbose "Created default output folder." }
                     catch { Write-Error "Failed to create default output folder '$VertexDefaultOutputFolder'. Cannot generate image. Error: $($_.Exception.Message)"; continue }
                }

                # Prepare parameters for Start-VertexImageGeneration
                $vertexParams = @{
                    ProjectId    = $VertexProjectId
                    LocationId   = $VertexLocationId
                    Prompt       = $imageGenPrompt
                    OutputFolder = $VertexDefaultOutputFolder
                }
                # Add optional params if needed, potentially parsed from $imageGenPrompt
                # Example: if ($imageGenPrompt -match '--model\s+(\S+)') { $vertexParams.ModelId = $Matches[1] }
                if ($PSBoundParameters.ContainsKey('Verbose')) { $vertexParams.Verbose = $true }

                # Call the image generation function
                Start-VertexImageGeneration @vertexParams

                # Skip the rest of the loop (Gemini API call, history update)
                Write-Host "------------------------------------------" -ForegroundColor Cyan
                continue
            } elseif ($commandExecuted) {
                 # If a command like /history, /clear, /config was executed, skip the API call
                 Write-Host "------------------------------------------" -ForegroundColor Cyan
                 continue
            }

            # --- Make API Call (Only if input was provided and not a command that should skip the API call) ---
            if ($currentPromptInput -ne $null) {
                 $lastUserPrompt = $currentPromptInput # Store for potential retry
                 # Prepare parameters, including any media added via /media in the previous iteration
                 $invokeParams = @{ ApiKey = $ApiKey; Model = $sessionConfig.Model; TimeoutSec = $TimeoutSec; MaxRetries = $MaxRetries; InitialRetryDelaySec = $InitialRetryDelaySec; Prompt = $currentPromptInput; ConversationHistory= $conversationHistory }; if ($PSBoundParameters.ContainsKey('GenerationConfig')) { $invokeParams.GenerationConfig = $GenerationConfig }; if ($currentImageFolder) { $invokeParams.ImageFolder = $currentImageFolder }; if ($currentVideoFolder) { $invokeParams.VideoFolder = $currentVideoFolder }; if ($currentRecurse) { $invokeParams.Recurse = $true }; if ($currentInlineFilePaths) { $invokeParams.InlineFilePaths = $currentInlineFilePaths } # Use sessionConfig.Model

                 # --- MODIFIED SECTION (Multi-step string construction) ---
                 # Calculate the current turn number
                 $turnNumber = ($conversationHistory.Count / 2) + 1

                 # Start building the debug message string
                 $debugMessage = "[DEBUG] Sending Prompt to Gemini (Turn $turnNumber):`n" + $invokeParams.Prompt

                 # Append the media indicator conditionally
                 if ($currentImageFolder -or $currentVideoFolder -or $currentInlineFilePaths) {
                     $debugMessage += " `n(With Media)"
                 }

                 # Write the debug message
                 Write-Host $debugMessage -ForegroundColor DarkYellow

                 # Write the thinking message
                 Write-Host "Gemini is thinking..." -ForegroundColor DarkGray
                 # --- END MODIFIED SECTION ---

                 $timerJob = Start-Job -ScriptBlock { Start-Sleep -Seconds 3600 }; try { $apiResult = Invoke-GeminiApi @invokeParams; $lastApiResult = $apiResult } finally { Stop-Job -Job $timerJob -EA SilentlyContinue; Remove-Job -Job $timerJob -Force -EA SilentlyContinue; Write-Host "`r".PadRight([Console]::WindowWidth - 1); Write-Host "`r" -NoNewline } # Store result
                 if ($apiResult -ne $null -and $apiResult.Success) {
                     Write-Host "`nGemini:" -F Green; Write-Host $apiResult.GeneratedText -F Green
                     $conversationHistory = $apiResult.UpdatedConversationHistory
                     Write-Verbose "History updated."
                     if ($PSBoundParameters.ContainsKey('OutputFile')) {
                         try {
                             $outputContent = "`n--- Turn $(($conversationHistory.Count / 2)) ($(Get-Date)) ---`nYou:`n$currentPromptInput`n`nGemini:`n$($apiResult.GeneratedText)`n"
                             $outputContent | Out-File -FilePath $OutputFile -Append -Encoding UTF8 -EA Stop
                             Write-Verbose "Appended turn to log."
                         } catch { Write-Warning "Failed append turn to '$OutputFile': $($_.Exception.Message)" }
                     }
                 }
                 else {
                     Write-Error "API call failed."
                     if ($apiResult -ne $null) {
                         if ($apiResult.StatusCode) { Write-Error "  Status: $($apiResult.StatusCode)" }
                         if ($apiResult.ResponseBody) { Write-Error "  Body: $($apiResult.ResponseBody)" }
                         if ($apiResult.ErrorRecord) { Write-Error "  Details: $($apiResult.ErrorRecord.Exception.Message)" }
                     } else { Write-Error "  Invoke-GeminiApi returned null." }
                     Write-Warning "History may not be updated."
                     if ($PSBoundParameters.ContainsKey('OutputFile')) {
                         try {
                             $statusCodeInfo = if($apiResult){"Status: $($apiResult.StatusCode)"}else{"N/A"}
                             $exceptionInfo = if($apiResult -and $apiResult.ErrorRecord){"Exception: $($apiResult.ErrorRecord.Exception.Message)"}else{"N/A"}
                             $responseBodyInfo = if($apiResult){"Body:`n$($apiResult.ResponseBody)"}else{"Body: N/A"}
                             $errorContent="`n--- Turn $(($conversationHistory.Count / 2) + 1) ($(Get-Date)) - API ERROR ---`nYou:`n$currentPromptInput`n`nGemini ERROR:`n$statusCodeInfo`n$exceptionInfo`n$responseBodyInfo`n--- End Error ---`n"
                             $errorContent|Out-File -FilePath $OutputFile -Append -Encoding UTF8 -EA Stop
                             Write-Verbose "Appended API error to log."
                         }catch{Write-Warning "Failed append API error to '$OutputFile': $($_.Exception.Message)"}
                     }
                 }
                 # --- Reset Media Variables for the NEXT turn ---
                 # This happens *after* the API call for the current turn is complete
                 $currentImageFolder = $null; $currentVideoFolder = $null; $currentRecurse = $false; $currentInlineFilePaths = $null

                 Write-Host "------------------------------------------" -ForegroundColor Cyan
            }

        } # End while ($true)
    } finally { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose "[Start-GeminiChat] Restoring original `$VerbosePreference ('$originalVerbosePreference')."; $VerbosePreference = $originalVerbosePreference } }
    # Final summary of errors
    if ($globalRenameErrors.Count -gt 0) { Write-Warning "$($globalRenameErrors.Count) rename error(s) occurred:" ; $globalRenameErrors | ForEach-Object { Write-Warning "- $_" } } # Use ForEach-Object alias %
    if ($globalMetadataErrors.Count -gt 0) { Write-Warning "$($globalMetadataErrors.Count) metadata error(s) occurred:"; $globalMetadataErrors | ForEach-Object { Write-Warning "- $_" } } # Use ForEach-Object alias %

    # --- Final Export to CSV if requested ---
    if ($sessionConfig.CsvOutputFile -and $conversationHistory.Count -gt 0) { Save-ChatToCsv -ConversationHistory $conversationHistory -CsvOutputFile $sessionConfig.CsvOutputFile }
    elseif ($sessionConfig.CsvOutputFile) { Write-Warning "Final CSV export skipped: Conversation history is empty." }
    Write-Host "`nExiting Gemini chat session." -ForegroundColor Cyan
    return $conversationHistory
}

# --- NEW HELPER: Save Conversation to CSV ---
function Save-ChatToCsv {
    param(
        [Parameter(Mandatory=$true)][array]$ConversationHistory,
        [Parameter(Mandatory=$true)][string]$CsvOutputFile
    )
    Write-Host "`nExporting conversation history to CSV: $CsvOutputFile" -ForegroundColor Cyan
    try {
        $csvData = [System.Collections.ArrayList]::new()
        $turnNumber = 0
        for ($i = 0; $i -lt $ConversationHistory.Count; $i++) {
            $turn = $ConversationHistory[$i]
            $role = $turn.role
            # Extract text, handling potential multiple parts (though usually one text part)
            $text = ($turn.parts | Where-Object { $_.text } | Select-Object -ExpandProperty text) -join "`n"
            # Increment turn number for each USER role
            if ($role -eq 'user') { $turnNumber++ }

            [void]$csvData.Add([PSCustomObject]@{
                Turn = $turnNumber
                Role = $role.ToUpper()
                Text = $text
            })
        }
        $csvData | Export-Csv -Path $CsvOutputFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "CSV export successful." -ForegroundColor Green
    } catch { Write-Error "Failed to export conversation history to CSV '$CsvOutputFile': $($_.Exception.Message)" }
}

# --- NEW HELPER: Parse Gemini Response ---
function Parse-GeminiResponse {
    param([string]$GeminiText)
    Write-Verbose "[Parse-GeminiResponse] Parsing response..."
    $parsedData = @{ Name = $null; Description = $null; Rating = $null; Location = $null; Tags = [System.Collections.ArrayList]::new(); Summary = $null; Chapters = $null } # Added Summary/Chapters
    if (-not [string]::IsNullOrWhiteSpace($GeminiText)) {
        $lines = $GeminiText -split '\r?\n'
        foreach ($line in $lines) {
            $trimmedLine = $line.Trim()
            # Use flexible regex parsing (same as used in modification logic before refactoring)
            if ($trimmedLine -match '^\s*(?:\*\*?)?(?:\d+\.\s*)?Name:\s*(.+?)\s*$') { $parsedData.Name = $Matches[1].Trim().Trim('*').Trim('_').Trim() }
            elseif ($trimmedLine -match '^\s*(?:\*\*?\s*\d+\.\s*)?Rating:\s*([0-5])') { $parsedData.Rating = [int]$Matches[1] }
            elseif ($trimmedLine -match '^\s*(?:\*\*?\s*\d+\.\s*)?(?:Tags:|Keywords:)\s*(.*)$') { $tagString = $Matches[1].Trim().Trim('*').Trim(); $tagsFromLine = $tagString -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 }; if ($tagsFromLine.Count -gt 0) { $tagsFromLine | ForEach-Object { [void]$parsedData.Tags.Add($_) } } }
            elseif ($trimmedLine -match '^\s*(?:\*\*?)?(?:\d+\.\s*)?Location:\s*(.+?)\s*$') { $parsedData.Location = $Matches[1].Trim().Trim('*').Trim() }
            elseif ($trimmedLine -match '^\s*(?:\*\*?\s*\d+\.\s*)?Description:\s*(.+)$') { $parsedData.Description = $Matches[1].Trim().Trim('*').Trim() }
            # Add parsing for Summary and Chapters if needed
            # elseif ($trimmedLine -match '^\s*(?:\*\*?)?(?:\d+\.\s*)?Summary:\s*(.+)$') { $parsedData.Summary = $Matches[1].Trim().Trim('*').Trim() }
            # elseif ($trimmedLine -match '^\s*(?:\*\*?)?(?:\d+\.\s*)?Chapters:\s*(.+)$') { $parsedData.Chapters = $Matches[1].Trim().Trim('*').Trim() }
        }
        # Log parsed data (optional)
        Write-Verbose "[Parse-GeminiResponse] Parsed Name: $($parsedData.Name)"
        Write-Verbose "[Parse-GeminiResponse] Parsed Rating: $($parsedData.Rating)"
        Write-Verbose "[Parse-GeminiResponse] Parsed Tags ($($parsedData.Tags.Count)): $($parsedData.Tags -join ', ')"
        Write-Verbose "[Parse-GeminiResponse] Parsed Location: $($parsedData.Location)"
        Write-Verbose "[Parse-GeminiResponse] Parsed Description: $(if ($parsedData.Description) { $parsedData.Description.Substring(0, [System.Math]::Min($parsedData.Description.Length, 50)) + '...' } else { '(null)' })"
    } else { Write-Warning "[Parse-GeminiResponse] Response text is empty." }
    return [PSCustomObject]$parsedData
}

# --- NEW HELPER: Save Parsed Results to CSV ---
function Save-ParsedResultsToCsv {
    param(
        [Parameter(Mandatory=$true)][System.IO.FileInfo]$OriginalFileInfo,
        [Parameter(Mandatory=$true)]$ParsedData, # Expects the PSCustomObject from Parse-GeminiResponse
        [Parameter(Mandatory=$true)][string]$ResultsCsvFilePath
    )
    Write-Verbose "[Save-ParsedResultsToCsv] Saving parsed results for '$($OriginalFileInfo.Name)' to '$ResultsCsvFilePath'"
    try {
        # Define the data to save
        $outputObject = [PSCustomObject]@{
            OriginalFilename = $OriginalFileInfo.Name
            ParsedName       = $ParsedData.Name
            ParsedDescription= $ParsedData.Description
            ParsedRating     = $ParsedData.Rating
            ParsedLocation   = $ParsedData.Location
            ParsedTags       = $ParsedData.Tags -join '; ' # Join tags into a single string for CSV
            # Add Summary and Chapters if they are parsed
            # ParsedSummary    = $ParsedData.Summary
            # ParsedChapters   = $ParsedData.Chapters
        }
        # Check if file exists and is empty to write header
        $writeHeader = (-not (Test-Path -LiteralPath $ResultsCsvFilePath)) -or ((Get-Item -LiteralPath $ResultsCsvFilePath).Length -eq 0)
        # Append data to CSV
        $outputObject | Export-Csv -Path $ResultsCsvFilePath -NoTypeInformation -Encoding UTF8 -Append:(-not $writeHeader) -ErrorAction Stop # Use -Append based on header status
        Write-Verbose "[Save-ParsedResultsToCsv] Successfully saved results for '$($OriginalFileInfo.Name)'."
    } catch { Write-Warning "[Save-ParsedResultsToCsv] Failed to save parsed results for '$($OriginalFileInfo.Name)' to '$ResultsCsvFilePath': $($_.Exception.Message)" }
}

# --- Vertex AI Image Generation Function ---
<#
.SYNOPSIS
Generates images using the Google Cloud Vertex AI Imagen API.
.DESCRIPTION
This function calls the Vertex AI Imagen API to generate images based on a text prompt.
It requires the Google Cloud SDK (`gcloud`) to be installed and authenticated
(e.g., via `gcloud auth application-default login`).
Generated images are saved to the specified output folder.

.PARAMETER ProjectId
[string] Your Google Cloud Project ID.
.PARAMETER LocationId
[string] The Google Cloud location ID for the Vertex AI endpoint (e.g., 'us-central1').
.PARAMETER Prompt
[string] The text prompt describing the image(s) to generate.
.PARAMETER NegativePrompt
[string] Optional. A text prompt describing elements to avoid in the generated images.
.PARAMETER OutputFolder
[string] The folder where generated images should be saved. The folder will be created if it doesn't exist.
.PARAMETER Count
[int] The number of images to generate (typically 1-8, depending on the model). Defaults to 1.
.PARAMETER ModelId
[string] The specific Vertex AI Imagen model ID to use (e.g., 'imagegeneration@006'). Defaults to 'imagegeneration@006'.
.PARAMETER Size
[string] Optional. The desired dimensions of the image (e.g., '1024x1024', '1536x1536'). Defaults depend on the model. Check Vertex AI documentation for supported sizes.
.PARAMETER OutputFileNameBase
[string] Optional. Base name for the output files. Defaults to a sanitized version of the prompt.
.PARAMETER AspectRatio
[string] Optional. Desired aspect ratio (e.g., "1:1", "16:9", "9:16"). Check Vertex AI documentation for supported ratios.
.PARAMETER Seed
[int] Optional. A seed value for deterministic generation.

.EXAMPLE
PS C:\> Start-VertexImageGeneration -ProjectId "your-gcp-project" -LocationId "us-central1" -Prompt "A photorealistic image of a red panda climbing a bamboo stalk" -OutputFolder "C:\GeneratedImages" -Count 2 -Size "1024x1024" -Verbose

.EXAMPLE
PS C:\> Start-VertexImageGeneration -ProjectId "your-gcp-project" -LocationId "us-central1" -Prompt "Impressionist painting of a rainy street in Paris" -NegativePrompt "cars, people" -OutputFolder "C:\Art" -AspectRatio "16:9"

.NOTES
Requires `gcloud` CLI installed and authenticated. Uses `gcloud auth print-access-token`.
Ensure the specified Vertex AI model and location support image generation.
Refer to Google Cloud Vertex AI documentation for the latest model IDs, supported parameters, and pricing.
Error handling for API responses is included.
Saves images as PNG files.
#>
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
    if (-not $gcloudPath) {
        Write-Error "Google Cloud SDK ('gcloud') not found in PATH. Please install and authenticate it (e.g., 'gcloud auth application-default login')."
        return
    }
    Write-Verbose "Using gcloud found at: $($gcloudPath.Path)"

    # --- Get Access Token ---
    Write-Verbose "Attempting to get access token via 'gcloud auth print-access-token'..."
    try {
        $accessToken = (gcloud auth print-access-token --quiet)
        if ([string]::IsNullOrWhiteSpace($accessToken)) { throw "Received empty access token." }
        Write-Verbose "Successfully obtained access token."
    } catch {
        Write-Error "Failed to get access token using 'gcloud auth print-access-token'. Ensure you are authenticated. Error: $($_.Exception.Message)"
        return
    }

    # --- Prepare Output Folder ---
    try {
        if (-not (Test-Path -LiteralPath $OutputFolder -PathType Container)) {
            Write-Warning "Output folder '$OutputFolder' does not exist. Creating..."
            New-Item -Path $OutputFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Verbose "Created output folder: $OutputFolder"
        }
    } catch {
        Write-Error "Failed to create output folder '$OutputFolder'. Error: $($_.Exception.Message)"
        return
    }

    # --- Construct API Request ---
    $apiUrl = "https://${LocationId}-aiplatform.googleapis.com/v1/projects/${ProjectId}/locations/${LocationId}/publishers/google/models/${ModelId}:predict"
    Write-Verbose "Using Vertex AI endpoint: $apiUrl"

    $requestBody = @{
        instances = @(
            @{ prompt = $Prompt }
        )
        parameters = @{
            sampleCount = $Count
        }
    }
    # Add optional parameters
    if (-not [string]::IsNullOrWhiteSpace($NegativePrompt)) { $requestBody.parameters.negativePrompt = $NegativePrompt }
    if ($PSBoundParameters.ContainsKey('Size')) {
        $dims = $Size -split 'x'
        if ($dims.Length -eq 2 -and $dims[0] -as [int] -ne $null -and $dims[1] -as [int] -ne $null) {
            $requestBody.parameters.add('width', [int]$dims[0])
            $requestBody.parameters.add('height', [int]$dims[1])
        } else { Write-Warning "Invalid -Size format '$Size'. Expected 'WidthxHeight' (e.g., '1024x1024'). Ignoring size parameter." }
    }
    if ($PSBoundParameters.ContainsKey('AspectRatio')) { $requestBody.parameters.aspectRatio = $AspectRatio }
    if ($PSBoundParameters.ContainsKey('Seed')) { $requestBody.parameters.seed = $Seed }

    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json; charset=utf-8"
    }
    $requestBodyJson = $requestBody | ConvertTo-Json -Depth 5
    Write-Verbose "Request Body JSON: $requestBodyJson"

    # --- Call API ---
    Write-Host "Sending request to Vertex AI Imagen API (Model: $ModelId)..." -ForegroundColor DarkGray
    $response = $null; $apiError = $null
    try {
        $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $requestBodyJson -ContentType "application/json; charset=utf-8" -TimeoutSec 300 -ErrorAction Stop
    } catch {
        $apiError = $_
        Write-Error "Vertex AI API call failed: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            # Attempt to read error response body
            $errorBody = $null
            try {
                $errorResponse = $_.Exception.Response
                # Read the stream directly if possible
                $stream = $errorResponse.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $errorBody = $reader.ReadToEnd()
                $reader.Close() # Close the reader
                if (-not [string]::IsNullOrWhiteSpace($errorBody)) {
                    Write-Error "Error Response Body: $errorBody"
                }
            } catch { Write-Warning "Could not read error response body stream: $($_.Exception.Message)" }
        }
        return # Stop execution on API error
    }

    # --- Process Response and Save Images ---
    if ($response -ne $null -and $response.predictions -is [array] -and $response.predictions.Count -gt 0) {
        Write-Host "API call successful. Processing $($response.predictions.Count) generated image(s)..." -ForegroundColor Green
        $baseFileName = if ([string]::IsNullOrWhiteSpace($OutputFileNameBase)) { Sanitize-Filename -InputString $Prompt -MaxLength 50 } else { Sanitize-Filename -InputString $OutputFileNameBase }
        $imageIndex = 0
        foreach ($prediction in $response.predictions) {
            $imageIndex++
            if ($prediction.bytesBase64Encoded) {
                try {
                    $imageBytes = [System.Convert]::FromBase64String($prediction.bytesBase64Encoded)
                    $outputFilePath = Join-Path -Path $OutputFolder -ChildPath "$($baseFileName)_$($imageIndex).png" # Assume PNG output
                    [System.IO.File]::WriteAllBytes($outputFilePath, $imageBytes)
                    Write-Host "Saved image: $outputFilePath" -ForegroundColor DarkGreen
                    # --- ADDED: Open the saved image ---
                    Invoke-Item -Path $outputFilePath
                } catch {
                    Write-Warning "Failed to decode or save image $imageIndex`: $($_.Exception.Message)"
                }
            } else {
                Write-Warning "Prediction $imageIndex did not contain expected 'bytesBase64Encoded' data."
            }
        }
    } else {
        Write-Warning "API response received, but no predictions found or response structure was unexpected."
        Write-Verbose "Full Response: $($response | ConvertTo-Json -Depth 5)"
    }
}

# --- Example Call Section ---
# Define default values for example calls.
# The script will check if these variables exist in the calling scope first.
if (-not (Get-Variable -Name 'examplePrompt' -ErrorAction SilentlyContinue)) {
    $examplePrompt = @"
No other text, Analyze the provided file:
1. Suggest an emotional descriptive filename with at least 5 to 10 words based on the content, prefixed with 'Name:'. Use underscores for spaces. Example: Name: Golden_Retriever_Playing
2. Suggest an emotional description between 100 and 500 words long, prefixed with 'Description:'. Example: Description: A golden retriever playing fetch in a sunny park, full of joy and energy.
3. Rate the file's quality (0-5), prefixed with 'Rating:'. Example: Rating: 5
4. List 30-50 important keywords, more specific first, using this criteria: main subject, secondary elements, location, actions/verbs, concepts/emotions, demographics if people are present, technical/style, orienation/format. Prefixed with 'Tags:'. Example: Tags: dog, golden retriever, playing, park, fetch
"@
}
if (-not (Get-Variable -Name 'myMediaFolder' -ErrorAction SilentlyContinue)) {
    $myMediaFolder = 'G:\My Drive\All Life Matters\Photos\Review_Photos' # ADJUST THIS PATH
}
if (-not (Get-Variable -Name 'myLogFile' -ErrorAction SilentlyContinue)) {
    $myLogFile = "$myMediaFolder\gemini_unified_log_v3.0.txt"            # ADJUST THIS PATH if needed
}
if (-not (Get-Variable -Name 'myAuthor' -ErrorAction SilentlyContinue)) {
    $myAuthor = "Steven Stoddard"
}
if (-not (Get-Variable -Name 'vertexProjectID' -ErrorAction SilentlyContinue)) {
    $vertexProjectID = "vertex-image-generation"                         # Replace with your actual Project ID
}
if (-not (Get-Variable -Name 'vertexLocationId' -ErrorAction SilentlyContinue)) {
    $vertexLocationId = "us-central1"
}
if (-not (Get-Variable -Name 'vertexDefaultOutputFolder' -ErrorAction SilentlyContinue)) {
    $vertexDefaultOutputFolder = "$myMediaFolder\GeneratedImages"         # ADJUST THIS PATH if needed
}
if (-not (Get-Variable -Name 'ExifToolPath' -ErrorAction SilentlyContinue)) {
    $ExifToolPath = "G:\My Drive\All Life Matters\Photos\exiftool-13.29_64\exiftool.exe" # ADJUST THIS PATH if needed
}

# Set API Key securely (e.g., $env:GEMINI_API_KEY or prompt)
# Check for API Key (prioritize calling scope variable, then environment, then error)
if (Get-Variable -Name 'apiKey' -ErrorAction SilentlyContinue) {
    Write-Verbose "Using \$apiKey from calling scope."
} elseif ($env:GEMINI_API_KEY) {
    $apiKey = $env:GEMINI_API_KEY
    Write-Verbose "Using \$apiKey from environment variable."
} else {
    Write-Error "API Key missing. Please define `$apiKey in your scope or set `$env:GEMINI_API_KEY."
    # Optionally exit or handle error
}

# --- Example Execution Options ---
# Uncomment ONE of the blocks below to run an example, or call Start-GeminiChat directly.

# Example 1: Process files with modifications (requires ExifTool)
<#
if ($apiKey -and (Test-Path $myMediaFolder)) {
    Write-Host "`n--- Running Example 1: File Processing with Modifications ---`n" -ForegroundColor Yellow
    Start-GeminiChat -ApiKey $apiKey -Model 'gemini-1.5-flash-latest' `
        -StartPrompt $examplePrompt -MediaFolder $myMediaFolder -ModifyFiles `
        -UpdateTitle -UpdateAuthor -AuthorName $myAuthor -UpdateSubject -UpdateTags `
        -UpdateRating -UpdateLocation -UpdateDescription `
        -ExifToolPath $ExifToolPath -OutputFile $myLogFile -FileDelaySec 1 -Verbose
} elseif ($apiKey) { Write-Warning "Media folder '$myMediaFolder' not found or not defined for Example 1." }
#>

# Example 2: Start chat configured for image generation (requires gcloud auth)
#<#
if ($apiKey -and $vertexProjectID -and $vertexLocationId -and $vertexDefaultOutputFolder) {
    Write-Host "`n--- Running Example 2: Interactive Chat with Image Generation Enabled ---`n" -ForegroundColor Yellow
    Start-GeminiChat -ApiKey $apiKey -VertexProjectId $vertexProjectID -VertexLocationId $vertexLocationId -VertexDefaultOutputFolder $vertexDefaultOutputFolder -Verbose
    # Then, during the chat, type: /generate A cat wearing a superhero cape
} elseif ($apiKey) { Write-Warning "Vertex AI parameters missing or not defined for Example 2." }
#>

# Example 3: Basic Interactive Chat (No initial files, no Vertex)
# <#
# if ($apiKey) {
#     Write-Host "`n--- Running Example 3: Basic Interactive Chat ---`n" -ForegroundColor Yellow
#     Start-GeminiChat -ApiKey $apiKey -Verbose
# }
# #>

Write-Host "`nScript loaded. Variables checked/defaults assigned. Uncomment an example block or call Start-GeminiChat directly." -ForegroundColor Green
