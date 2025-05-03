# FileProcessingUtils.ps1
# Contains functions for processing initial media files, interacting with ExifTool,
# parsing Gemini responses for file metadata, and saving parsed results.

#Requires -Version 5.1
# Requires ExifTool for modification/location features.

# Depends on CoreUtils.ps1 for Sanitize-Filename
# Depends on GeminiApiUtils.ps1 for Invoke-GeminiApi

# --- Helper: Get Start Media Files (with exclusion) ---
function Get-StartMediaFiles {
    [CmdletBinding()]
    param(
        [string]$FolderPath,
        [switch]$Recurse,
        [string[]]$SupportedExtensions,
        [string]$MediaType,
        [string]$ExcludePath # Add parameter to exclude log file path
    )
    # ... (Get-StartMediaFiles function body from modular script v4.0.0) ...
    Write-Verbose "[Get-StartMediaFiles] Searching for $MediaType files in: $FolderPath $($Recurse.IsPresent ? '(Recursive)' : '')"
    $discoveredFiles = [System.Collections.ArrayList]::new()
    try {
        $gciParams = @{ Path = $FolderPath; File = $true; ErrorAction = 'Stop' }
        if ($Recurse.IsPresent) { $gciParams.Recurse = $true }
        $allFiles = Get-ChildItem @gciParams | Where-Object { $SupportedExtensions -contains $_.Extension.ToLowerInvariant() }
        foreach ($file in $allFiles) { if ($ExcludePath -and ($file.FullName -eq (Resolve-Path -LiteralPath $ExcludePath -EA SilentlyContinue))) { Write-Verbose "  [Get-StartMediaFiles] Skipping excluded file: $($file.Name)" } else { [void]$discoveredFiles.Add($file) } }
        Write-Verbose "[Get-StartMediaFiles] Found $($discoveredFiles.Count) $MediaType file(s) after exclusion."
        return $discoveredFiles.ToArray()
    } catch { Write-Error "[Get-StartMediaFiles] Failed search '$FolderPath': $($_.Exception.Message)"; return @() }
}

# --- Helper: Parse Gemini Response for File Metadata ---
function Parse-GeminiResponse {
    [CmdletBinding()]
    param(
        [string]$GeminiText
    )
    # ... (Parse-GeminiResponse function body from modular script v4.0.0) ...
    Write-Verbose "[Parse-GeminiResponse] Parsing response..."
    $parsedData = @{ Name = $null; Description = $null; Rating = $null; Location = $null; Tags = [System.Collections.ArrayList]::new() }
    if (-not [string]::IsNullOrWhiteSpace($GeminiText)) {
        $lines = $GeminiText -split '\r?\n'; foreach ($line in $lines) { $trimmedLine = $line.Trim()
            if ($trimmedLine -match '^\s*(?:\*\*?)?(?:\d+\.\s*)?(?i)Name:\s*(.+?)\s*$') { $parsedData.Name = $Matches[1].Trim('*_ ') }
            elseif ($trimmedLine -match '^\s*(?:\*\*?\s*\d+\.\s*)?(?i)Rating:\s*([0-5])') { $parsedData.Rating = [int]$Matches[1] }
            elseif ($trimmedLine -match '^\s*(?:\*\*?\s*\d+\.\s*)?(?i)(?:Tags:|Keywords:)\s*(.*)$') { $tagString=$Matches[1].Trim('*_ ');$tags=$tagString-split'[,;]'|%{$_.Trim()}|?{$_};if($tags){$tags|%{[void]$parsedData.Tags.Add($_)}}}
            elseif ($trimmedLine -match '^\s*(?:\*\*?)?(?:\d+\.\s*)?(?i)Location:\s*(.+?)\s*$') { $parsedData.Location = $Matches[1].Trim('*_ ') }
            elseif ($trimmedLine -match '^\s*(?:\*\*?\s*\d+\.\s*)?(?i)Description:\s*(.+)$') { $parsedData.Description = $Matches[1].Trim('*_ ') } }
        Write-Verbose "[Parse-GeminiResponse] Parsed Name: $($parsedData.Name), Rating: $($parsedData.Rating), Tags: $($parsedData.Tags.Count), Location: $($parsedData.Location), Desc: $(if($parsedData.Description){$parsedData.Description.Length}else{0}) chars."
    } else { Write-Warning "[Parse-GeminiResponse] Response text empty." }
    $parsedData.Tags = $parsedData.Tags.ToArray(); return [PSCustomObject]$parsedData
}

# --- Helper: Save Parsed Results to CSV ---
function Save-ParsedResultsToCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][System.IO.FileInfo]$OriginalFileInfo,
        [Parameter(Mandatory=$true)]$ParsedData,
        [Parameter(Mandatory=$true)][string]$ResultsCsvFilePath
    )
    # ... (Save-ParsedResultsToCsv function body from modular script v4.0.0) ...
    Write-Verbose "[Save-ParsedResultsToCsv] Saving parsed results for '$($OriginalFileInfo.Name)' to '$ResultsCsvFilePath'"
    try {
        $outputObject = [PSCustomObject]@{ OriginalFilename=$OriginalFileInfo.Name; ParsedName=$ParsedData.Name; ParsedDescription=$ParsedData.Description; ParsedRating=$ParsedData.Rating; ParsedLocation=$ParsedData.Location; ParsedTags=($ParsedData.Tags -join '; ') }
        $writeHeader = (-not (Test-Path -LiteralPath $ResultsCsvFilePath)) -or ((Get-Item -LiteralPath $ResultsCsvFilePath).Length -eq 0)
        $outputObject | Export-Csv -Path $ResultsCsvFilePath -NoTypeInformation -Encoding UTF8 -Append:(-not $writeHeader) -ErrorAction Stop
        Write-Verbose "[Save-ParsedResultsToCsv] Saved results for '$($OriginalFileInfo.Name)'."
    } catch { Write-Warning "[Save-ParsedResultsToCsv] Failed save results for '$($OriginalFileInfo.Name)': $($_.Exception.Message)" }
}


# --- Helper: GPS Reading via ExifTool ---
function Get-GpsFromExif {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][System.IO.FileInfo]$FileInfo,
        [Parameter(Mandatory=$true)][string]$ResolvedExifToolPath
    )
    # ... (Get-GpsFromExif function body from modular script v4.0.0) ...
    Write-Verbose "[Get-GpsFromExif] Reading GPS for '$($FileInfo.Name)'..."
    $gpsCoordsString = $null
    try {
        $imgExt = @('.jpg', '.jpeg', '.heic', '.heif', '.tiff', '.tif'); if (-not ($imgExt -contains $FileInfo.Extension.ToLowerInvariant())) { Write-Verbose " Skip GPS check for $($FileInfo.Extension)"; return $null }
        $args = @('-n', '-GPSLatitude', '-GPSLongitude', '-j', '-coordFormat', '%.6f', $FileInfo.FullName)
        $p = Start-Process -FilePath $ResolvedExifToolPath -ArgumentList $args -Wait -NoNewWindow -RedirectStandardOutput ($stdOut=New-TemporaryFile) -RedirectStandardError ($stdErr=New-TemporaryFile) -PassThru
        $out = Get-Content -Path $stdOut.FullName; $err = Get-Content -Path $stdErr.FullName; Remove-Item $stdOut.FullName, $stdErr.FullName -EA SilentlyContinue
        Write-Verbose " ExifTool GPS Read StdOut: $($out -join "`n ")"
        if ($p.ExitCode -ne 0 -or $err) { throw "ExifTool ExitCode $($p.ExitCode). Stderr: $($err -join '; ')" }
        $jsonData = $out -join "" | ConvertFrom-Json -EA SilentlyContinue; if ($jsonData -is [array]) { $jsonData = $jsonData[0] }
        if ($jsonData?.GPSLatitude -and $jsonData?.GPSLongitude -and $jsonData.GPSLatitude -ne 0 -and $jsonData.GPSLongitude -ne 0) { $lat=$jsonData.GPSLatitude.ToString("F6",[System.Globalization.CultureInfo]::InvariantCulture); $lon=$jsonData.GPSLongitude.ToString("F6",[System.Globalization.CultureInfo]::InvariantCulture); $gpsCoordsString="GPS: $lat, $lon"; Write-Verbose " Found GPS: $gpsCoordsString" }
        else { Write-Verbose " No valid GPS coords found." }
    } catch { Write-Warning "[Get-GpsFromExif] Error reading GPS for '$($FileInfo.Name)': $($_.Exception.Message)." }
    return $gpsCoordsString
}

# --- Helper: ExifTool Metadata Update Execution ---
function Invoke-ExifToolUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ResolvedExifToolPath,
        [Parameter(Mandatory=$true)][string]$CurrentFilePath,
        [Parameter(Mandatory=$true)]$ParsedData,
        [Parameter(Mandatory=$true)]$SessionConfig
    )
    # ... (Invoke-ExifToolUpdate function body from modular script v4.0.0) ...
    Write-Verbose "[Invoke-ExifToolUpdate] Updating metadata for '$CurrentFilePath'..."
    $success = $false
    try {
        $exifArgs = [System.Collections.ArrayList]::new(); $origBase = [System.IO.Path]::GetFileNameWithoutExtension($CurrentFilePath); $titleVal = if($ParsedData.Name){(Sanitize-Filename -InputString $ParsedData.Name) -replace '_',' '}else{$origBase}
        if($SessionConfig.UpdateTitle -and $ParsedData.Name){[void]$exifArgs.Add("-Title=`"$titleVal`"")}
        if($SessionConfig.UpdateAuthor -and $SessionConfig.AuthorName){[void]$exifArgs.Add("-Artist=`"$($SessionConfig.AuthorName)`"");[void]$exifArgs.Add("-Creator=`"$($SessionConfig.AuthorName)`"")}
        if($SessionConfig.UpdateRating -and $ParsedData.Rating -ne $null){if($ParsedData.Rating -in 0..5){[void]$exifArgs.Add("-Rating=$($ParsedData.Rating)")}else{Write-Warning "Invalid rating."}}
        if($SessionConfig.UpdateTags){[void]$exifArgs.Add("-Keywords=");[void]$exifArgs.Add("-Subject=");if($ParsedData.Tags.Count -gt 0){foreach($t in $ParsedData.Tags){[void]$exifArgs.Add("-Keywords=`"$t`"");[void]$exifArgs.Add("-Subject=`"$t`"")}}Write-Verbose " Setting $($ParsedData.Tags.Count) tags."}
        if($SessionConfig.UpdateLocation -and $ParsedData.Location){$locParts=$ParsedData.Location-split','|%{$_.Trim()}|?{$_};if($locParts.Count -gt 0){if($locParts[0]){[void]$exifArgs.Add("-City=`"$($locParts[0])`"")};if($locParts.Count-gt 1 -and $locParts[1]){[void]$exifArgs.Add("-State=`"$($locParts[1])`"")};if($locParts.Count-gt 2 -and $locParts[2]){[void]$exifArgs.Add("-Country=`"$($locParts[2])`"")};if(-not $SessionConfig.UpdateSubject -and -not $SessionConfig.UpdateDescription){[void]$exifArgs.Add("-Comment=`"$($ParsedData.Location)`"")}}else{Write-Warning "Cannot parse Location."}}
        if($SessionConfig.UpdateDescription -and $ParsedData.Description){[void]$exifArgs.Add("-Description=`"$($ParsedData.Description)`"");[void]$exifArgs.Add("-Comment=`"$($ParsedData.Description)`"")}
        elseif($SessionConfig.UpdateSubject -and $ParsedData.Name){[void]$exifArgs.Add("-Comment=`"$titleVal`"")}

        if ($exifArgs.Count -gt 0) {
            [void]$exifArgs.Add("-overwrite_original"); [void]$exifArgs.Add("-m"); [void]$exifArgs.Add($CurrentFilePath); Write-Verbose " Executing ExifTool ($($exifArgs.Count - 3) tags)..."
            $exifResult = & $ResolvedExifToolPath @exifArgs 2>&1; Write-Verbose " ExifTool Output: $($exifResult -join "`n ")"
            if($LASTEXITCODE -eq 0 -and ($exifResult -match '1\s+(image|video|audio|document|file)\s+files?\s+updated')){ Write-Host "[Metadata Updated: $(Split-Path $CurrentFilePath -Leaf)]" -F DarkGreen; $success = $true }
            else{ throw "ExifTool failed (ExitCode: $LASTEXITCODE). Output: $($exifResult -join '; ')" }
        } else { Write-Host "[Metadata Unchanged: $(Split-Path $CurrentFilePath -Leaf)]" -F DarkGray; $success = $true }
    } catch { Write-Warning "[Invoke-ExifToolUpdate] Failed update '$CurrentFilePath': $($_.Exception.Message)"; $success = $false }
    return $success
}


# --- Helper: File Rename and Metadata Update Orchestration ---
function Update-FileWithGeminiResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][System.IO.FileInfo]$FileInfo,
        [Parameter(Mandatory=$true)]$ParsedData,
        [Parameter(Mandatory=$true)]$SessionConfig,
        [Parameter(Mandatory=$true)]$GlobalRenameErrors,
        [Parameter(Mandatory=$true)]$GlobalMetadataErrors
    )
    # ... (Update-FileWithGeminiResults function body from modular script v4.0.0) ...
    # (Ensure it uses Sanitize-Filename from CoreUtils.ps1 and Invoke-ExifToolUpdate from this file)
    Write-Verbose "[Update-FileWithGeminiResults] Checking mods for '$($FileInfo.Name)'..."
    $processedCount=0;$skippedCount=0
    if (-not ($SessionConfig.ModifyFiles -and $SessionConfig.ExifToolPath)) { Write-Verbose " Skipping mods."; return @{Processed=$processedCount;Skipped=$skippedCount} }
    $origExt=$FileInfo.Extension;$origBase=[System.IO.Path]::GetFileNameWithoutExtension($FileInfo.Name);$namePart=if($ParsedData.Name){Sanitize-Filename -InputString $ParsedData.Name}else{$null}
    $locPart=if($SessionConfig.UpdateLocation -and $ParsedData.Location){Sanitize-Filename -InputString $ParsedData.Location -MaxLength 50}else{$null}
    $ratingPart=if($SessionConfig.UpdateRating -and $ParsedData.Rating -ne $null){"Rating$($ParsedData.Rating)"}else{$null}
    $newNameParts=[System.Collections.ArrayList]::new();if($namePart){[void]$newNameParts.Add($namePart)}else{[void]$newNameParts.Add($origBase)};if($locPart){[void]$newNameParts.Add($locPart)};if($ratingPart){[void]$newNameParts.Add($ratingPart)};if($newNameParts.Count-eq 0){[void]$newNameParts.Add($origBase)}
    $newNameBase=$newNameParts -join '_';$newName="$($newNameBase)$($origExt)";$newPath=Join-Path $FileInfo.DirectoryName $newName
    $isRename=$newName -ne $FileInfo.Name;$anyUpdate=$SessionConfig.UpdateTitle -or $SessionConfig.UpdateAuthor -or $SessionConfig.UpdateSubject -or $SessionConfig.UpdateTags -or $SessionConfig.UpdateRating -or $SessionConfig.UpdateLocation -or $SessionConfig.UpdateDescription
    $hasData=($SessionConfig.UpdateTitle -and $ParsedData.Name) -or ($SessionConfig.UpdateAuthor -and $SessionConfig.AuthorName) -or ($SessionConfig.UpdateSubject -and $ParsedData.Name) -or ($SessionConfig.UpdateTags -and $ParsedData.Tags.Count -gt 0) -or ($SessionConfig.UpdateRating -and $ParsedData.Rating -ne $null) -or ($SessionConfig.UpdateDescription -and $ParsedData.Description) -or ($SessionConfig.UpdateLocation -and $ParsedData.Location)
    $isMetaUpdate=$anyUpdate -and $hasData
    $proceed=$false
    if ($isRename -or $isMetaUpdate) {
        $isConflict=$isRename -and (Test-Path -LiteralPath $newPath -PathType Leaf)
        Write-Host "`n--- Proposed Changes for '$($FileInfo.Name)' ---" -F Yellow;$rnmMsg=if(-not $isRename){"Metadata only"}else{"'$($FileInfo.Name)' -> '$newName'"};$metaMsgs=@();if($SessionConfig.UpdateTitle -and $ParsedData.Name){$metaMsgs+="Title"};if($SessionConfig.UpdateAuthor){$metaMsgs+="Author"};if($SessionConfig.UpdateSubject -and $ParsedData.Name){$metaMsgs+="Subject"};if($SessionConfig.UpdateTags){$metaMsgs+=if($ParsedData.Tags.Count -gt 0){"Tags($($ParsedData.Tags.Count))"}else{"ClearTags"}};if($SessionConfig.UpdateRating -and $ParsedData.Rating -ne $null){$metaMsgs+="Rating"};if($SessionConfig.UpdateLocation -and $ParsedData.Location){$metaMsgs+="LocMeta"};if($SessionConfig.UpdateDescription -and $ParsedData.Description){$metaMsgs+="Desc"};$metaMsg=if($metaMsgs){" ($($metaMsgs -join ', '))"}else{""}
        if($isConflict){Write-Host "[CONFLICT] $rnmMsg" -F Red}else{Write-Host "$rnmMsg$metaMsg" -F Cyan};Write-Host "---" -F Yellow
        if($isConflict){Write-Warning "Skipped (conflict).";$skippedCount++}elseif($SessionConfig.ConfirmModifications){if((Read-Host "Proceed?(y/N)")-eq 'y'){$proceed=$true}else{Write-Host Aborted -F Yellow;$skippedCount++}}else{Write-Host Proceeding -F Yellow;$proceed=$true}
    } else { Write-Verbose " No changes proposed." }
    if ($proceed) {
        $curPath=$FileInfo.FullName;$renameOK=$true;$metaOK=$true
        if($isRename){try{Rename-Item -LiteralPath $curPath -NewName $newName -EA Stop;Write-Host "[Renamed -> '$newName']" -F DarkGray;$curPath=$newPath}catch{$errMsg="Failed rename: $($_.Exception.Message)";Write-Warning $errMsg;[void]$GlobalRenameErrors.Add($errMsg);$renameOK=$false;$skippedCount++}}
        if($renameOK -and $isMetaUpdate){$metaOK = Invoke-ExifToolUpdate -ResolvedExifToolPath $SessionConfig.ExifToolPath -CurrentFilePath $curPath -ParsedData $ParsedData -SessionConfig $SessionConfig;if(-not $metaOK){[void]$GlobalMetadataErrors.Add("Meta update failed for '$curPath'")}}
        if(($isRename -and $renameOK) -or ($isMetaUpdate -and $metaOK)){if($skippedCount -eq 0){$processedCount++}}elseif($isRename -and -not $renameOK){ }elseif($isMetaUpdate -and -not $metaOK){$skippedCount++}
    }
    return @{Processed=$processedCount;Skipped=$skippedCount}
}

# --- Helper: Process Initial Media Files Orchestrator ---
function Process-InitialMediaFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$SessionConfig,
        [Parameter(Mandatory=$true)]$ApiKey,
        [Parameter(Mandatory=$true)]$StartPrompt,
        [Parameter(Mandatory=$true)]$GlobalRenameErrors,
        [Parameter(Mandatory=$true)]$GlobalMetadataErrors
    )
    # ... (Process-InitialMediaFiles function body from modular script v4.0.0) ...
    # (Uses Get-StartMediaFiles, Get-GpsFromExif, Invoke-GeminiApi, Parse-GeminiResponse, Update-FileWithGeminiResults, Save-ParsedResultsToCsv)
    Write-Host "`nProcessing initial files in '$($SessionConfig.MediaFolder)'$($SessionConfig.RecurseFiles?'(Recursive)':'')..." -F Yellow; Write-Host "Base Prompt: $StartPrompt" -F White
    $processed=0;$skipped=0;$discovered=[System.Collections.ArrayList]::new();$map=@{image=@('.jpg','.jpeg','.png','.webp','.gif','.heic','.heif','.bmp','.tif','.tiff');video=@('.mp4','.mpeg','.mov','.avi','.flv','.mpg','.webm','.wmv','.3gp','.3gpp','.mkv');audio=@('.mp3','.wav','.ogg','.flac','.m4a','.aac','.wma');document=@('.txt','.pdf','.html','.htm','.json','.csv','.xml','.rtf','.md')}
    $excludePath = if($SessionConfig.OutputFile){Resolve-Path -Lit $SessionConfig.OutputFile -EA SilentlyContinue}else{$null}
    foreach($type in $map.Keys){$found=Get-StartMediaFiles -FolderPath $SessionConfig.MediaFolder -Recurse:$SessionConfig.RecurseFiles -SupportedExtensions $map[$type] -MediaType $type -ExcludePath $excludePath; if($found){Write-Host "($($found.Count) $type file(s))" -F Gray;$found.ForEach({[void]$discovered.Add($_)})}}
    if($discovered.Count -eq 0){Write-Warning "No supported files found."; return $false}

    $idx=0;$total=$discovered.Count; Write-Progress -Activity "Processing Media" -Status "Starting..." -PercentComplete 0
    foreach($fileInfo in $discovered){
        $idx++;$fPath=$fileInfo.FullName;Write-Host "`nProcessing File $idx/$total`: $($fileInfo.Name)" -F Cyan;Write-Progress -Activity "Processing Media" -Status "Processing '$($fileInfo.Name)' ($idx/$total)" -PercentComplete (($idx/$total)*100)
        $prompt=$StartPrompt;$gpsStr=$null;if($SessionConfig.UpdateLocation -and $SessionConfig.ExifToolPath){$gpsStr=Get-GpsFromExif -FileInfo $fileInfo -ResolvedExifToolPath $SessionConfig.ExifToolPath;if($gpsStr){$locInstr="`n5. GPS($gpsStr): Determine Location (City, State, Country). Prefix 'Location:'.";$prompt+=$locInstr;Write-Verbose " Appended GPS prompt."}}elseif($SessionConfig.UpdateLocation){Write-Warning "Cannot read GPS."}
        $invokeParams=@{ApiKey=$ApiKey;Model=$SessionConfig.Model;TimeoutSec=$SessionConfig.TimeoutSec;MaxRetries=$SessionConfig.MaxRetries;InitialRetryDelaySec=$SessionConfig.InitialRetryDelaySec;Prompt=$prompt;InlineFilePaths=@($fPath);ConversationHistory=@()};if($SessionConfig.GenerationConfig){$invokeParams.GenerationConfig=$SessionConfig.GenerationConfig}
        Write-Host "[DEBUG] Prompt(File:$($fileInfo.Name)):`n$($invokeParams.Prompt)"-F DarkYellow;Write-Host "Gemini thinking..."-F DarkGray;$timer=Start-Job {Start-Sleep 999};try{$apiRes=Invoke-GeminiApi @invokeParams}finally{Stop-Job $timer -EA SilentlyContinue;Remove-Job $timer -Force -EA SilentlyContinue;Write-Host "`r".PadRight($Host.UI.RawUI.WindowSize.Width - 1);Write-Host "`r"-NoNewline}
        if($apiRes?.Success){
            Write-Host "Gemini Response:"-F Green;Write-Host $apiRes.GeneratedText -F Green;if($SessionConfig.OutputFile){try{"`n--- File '$($fileInfo.Name)' ($(Get-Date)) ---`nPROMPT:`n$($invokeParams.Prompt)`n`nRESPONSE:`n$($apiRes.GeneratedText)`n"|Out-File $SessionConfig.OutputFile -Append -Enc UTF8 -EA Stop}catch{Write-Warning "Failed log append."}}
            $parsed=Parse-GeminiResponse -GeminiText $apiRes.GeneratedText
            $modRes=Update-FileWithGeminiResults -FileInfo $fileInfo -ParsedData $parsed -SessionConfig $SessionConfig -GlobalRenameErrors $GlobalRenameErrors -GlobalMetadataErrors $GlobalMetadataErrors;$processed+=$modRes.Processed;$skipped+=$modRes.Skipped
            if($SessionConfig.ResultsCsvFile){Save-ParsedResultsToCsv -OriginalFileInfo $fileInfo -ParsedData $parsed -ResultsCsvFilePath $SessionConfig.ResultsCsvFile}
        }else{$err="API call failed for '$($fileInfo.Name)'.";if($apiRes){$err+=" Status:$($apiRes.StatusCode) Detail:$($apiRes.ErrorRecord.Exception.Message) Body:$($apiRes.ResponseBody)"}else{$err+=" Invoke-GeminiApi null."};Write-Error $err;$skipped++;if($SessionConfig.OutputFile){try{"`n--- File '$($fileInfo.Name)' ($(Get-Date)) - API ERROR ---`nPROMPT:`n$($invokeParams.Prompt)`n`nERROR:`n$err`n---"|Out-File $SessionConfig.OutputFile -Append -Enc UTF8 -EA Stop}catch{Write-Warning "Failed err log."}}}
        if($SessionConfig.FileDelaySec -gt 0 -and $idx -lt $total){Write-Verbose "Pausing $($SessionConfig.FileDelaySec)s...";Start-Sleep -Sec $SessionConfig.FileDelaySec}
    }
    Write-Progress -Activity "Processing Media" -Completed;Write-Host "`n--- Finished Initial Files ($processed modified, $skipped skipped) ---" -F Yellow;return $true
}

Write-Verbose "FileProcessingUtils.ps1 loaded."