# GeminiApiUtils.ps1
# Contains functions for interacting with the Google Gemini API.

#Requires -Version 5.1

# Depends on CoreUtils.ps1 for Get-MimeTypeFromFile

# --- Helper: Upload File via File API ---
function Upload-GeminiFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [Parameter(Mandatory = $true)][System.IO.FileInfo]$FileInfo,
        [int]$TimeoutSec = 180
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

    $progressScriptBlock = { param($FileName, $TotalSize, $ProgressId, $StartTime); while ($true) { $elapsed = (Get-Date) - $StartTime; $status = "Uploading '$FileName' ({0:F2} MB) - Elapsed: {1:hh\:mm\:ss}" -f ($TotalSize / 1MB), $elapsed; Write-Progress -Activity "Uploading via File API" -Status $status -Id $progressId -SecondsRemaining -1; Start-Sleep -Milliseconds 500 } }
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
        [string[]]$InlineFilePaths
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
        function Add-MediaPart {
            param([string]$ApiKey, [System.IO.FileInfo]$FileInfo, [long]$MaxSize, [System.Collections.ArrayList]$PartsList)
            $mimeType = Get-MimeTypeFromFile -FileInfo $FileInfo # From CoreUtils
            if ([string]::IsNullOrWhiteSpace($mimeType) -or $mimeType -eq 'application/octet-stream') { Write-Warning "[Invoke-GeminiApi] Invalid MIME type for '$($FileInfo.Name)'. Skipping."; return $false }
            if ($FileInfo.Length -lt $MaxSize) { Write-Verbose "[Invoke-GeminiApi] Encoding inline: '$($FileInfo.Name)'..."; $bytes = [System.IO.File]::ReadAllBytes($FileInfo.FullName); $b64 = [System.Convert]::ToBase64String($bytes); [void]$PartsList.Add(@{ inline_data = @{ mime_type = $mimeType; data = $b64 } }) }
            else { Write-Verbose "[Invoke-GeminiApi] Uploading large file: '$($FileInfo.Name)'..."; $uploadResult = Upload-GeminiFile -ApiKey $ApiKey -FileInfo $FileInfo; if ($uploadResult?.Success) { [void]$PartsList.Add(@{ file_data = @{ mime_type = $mimeType; file_uri = $uploadResult.FileUri } }) } else { throw "Failed to upload large file '$($FileInfo.Name)'. Error: $($uploadResult.ErrorRecord.Exception.Message)" } }
            return $true
        }
        # --- End Internal Helper ---

        try {
            $allMediaFiles = [System.Collections.ArrayList]::new()
            if ($PSBoundParameters.ContainsKey('InlineFilePaths') -and $InlineFilePaths) {
                Write-Verbose "[Invoke-GeminiApi] Processing -InlineFilePaths."
                foreach ($filePath in $InlineFilePaths) { if (Test-Path -LiteralPath $filePath -PathType Leaf) { [void]$allMediaFiles.Add((Get-Item -LiteralPath $filePath -EA Stop)) } else { Write-Warning "[Invoke-GeminiApi] File not found: '$filePath'." } }
            }
            elseif ($PSBoundParameters.ContainsKey('ImageFolder') -or $PSBoundParameters.ContainsKey('VideoFolder')) {
                 Write-Verbose "[Invoke-GeminiApi] Processing -ImageFolder/-VideoFolder..."
                 function Get-MediaFilesInternal { param([string]$Path, [switch]$Recurse, [string[]]$Ext) try { $p=@{Path=$Path;File=$true;EA='Stop'}; if($Recurse){$p.Recurse=$true}; (Get-ChildItem @p|Where{$Ext -contains $_.Extension.ToLowerInvariant()})}catch{Write-Error "Failed search '$Path': $($_.Exception.Message)";return $null}}
                 $imgExt = @('.jpg', '.jpeg', '.png', '.webp', '.gif', '.heic', '.heif', '.bmp', '.tif', '.tiff')
                 $vidExt = @('.mp4', '.mpeg', '.mov', '.avi', '.flv', '.mpg', '.webm', '.wmv', '.3gp', '.3gpp', '.mkv')
                 if ($PSBoundParameters.ContainsKey('ImageFolder')) { $imgFiles = Get-MediaFilesInternal -Path $ImageFolder -Recurse:$Recurse.IsPresent -Ext $imgExt; if ($imgFiles) { $imgFiles | ForEach-Object { [void]$allMediaFiles.Add($_) } } }
                 if ($PSBoundParameters.ContainsKey('VideoFolder') -and $VideoFolder -ne $ImageFolder) { $vidFiles = Get-MediaFilesInternal -Path $VideoFolder -Recurse:$Recurse.IsPresent -Ext $vidExt; if ($vidFiles) { $vidFiles | ForEach-Object { [void]$allMediaFiles.Add($_) } } }
                 Write-Verbose "[Invoke-GeminiApi] Found $($allMediaFiles.Count) media file(s) in folders."
            }
            else { Write-Verbose "[Invoke-GeminiApi] No media files provided." }

            foreach ($fileInfo in $allMediaFiles) { $addSuccess = Add-MediaPart -ApiKey $ApiKey -FileInfo $fileInfo -MaxSize $maxInlineDataSizeBytes -PartsList $currentUserParts; if (-not $addSuccess) { /* Optional: Handle specific skipping */ } }
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
                $webEx = $_; $statusCode = if ($webEx.Exception.Response) { [int]$webEx.Exception.Response.StatusCode } else { $null }; $result.ErrorRecord = $webEx; $result.StatusCode = $statusCode
                try { if ($webEx.Exception.Response) { $stream=$webEx.Exception.Response.GetResponseStream();$reader=New-Object IO.StreamReader($stream);$result.ResponseBody=$reader.ReadToEnd();$reader.Close(); if($statusCode -eq 400){Write-Error "[Invoke-GeminiApi] 400 Body: $($result.ResponseBody)"}Write-Verbose "[Invoke-GeminiApi] Error Body: $($result.ResponseBody)"}}catch{Write-Warning "No error body."}
                $errorMsg = "[Invoke-GeminiApi] Web exception (Status: $statusCode)."; if($statusCode -eq 400){$errorMsg+=" Check request."}; if($statusCode -eq 429 -and $currentRetry -lt $MaxRetries){$currentRetry++;$delay=($InitialRetryDelaySec*([Math]::Pow(2,$currentRetry-1)))+(Get-Random -Mi 0 -Ma 1000)/1000.0;Write-Warning "[Invoke-GeminiApi] 429. Retrying $currentRetry/$($MaxRetries+1) in $($delay.ToString('F2'))s...";Start-Sleep -Sec $delay;continue}else{Write-Error $errorMsg;break}
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