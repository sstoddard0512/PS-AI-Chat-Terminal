# ChatUtils.ps1
# Contains functions supporting the interactive chat loop, command handling,
# user input, API result processing, and Vertex AI configuration checks.

#Requires -Version 5.1

# Depends on CoreUtils.ps1, GeminiApiUtils.ps1, VertexApiUtils.ps1, FileProcessingUtils.ps1

# --- Helper: Get Chat Input ---
function Get-ChatInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][hashtable]$SessionConfig,
        [Parameter(Mandatory=$true)][bool]$IsFirstInteractiveTurn
    )
    if ($IsFirstInteractiveTurn) {
        # Display Help Text (Copied from Handle-ChatCommand /help case)
        Write-Host "`n--- Available Commands ---" -ForegroundColor Yellow
        Write-Host "  /history      - Display conversation history." -ForegroundColor Cyan
        Write-Host "  /clear        - Clear conversation history." -ForegroundColor Cyan
        Write-Host "  /retry        - Retry the last failed API call." -ForegroundColor Cyan
        Write-Host "  /config       - Show current session settings." -ForegroundColor Cyan
        Write-Host "  /save         - Save history to CSV (if -CsvOutputFile specified)." -ForegroundColor Cyan
        Write-Host "  /media [path] - Add media (folder/file) for the next prompt. If no path, prompts interactively." -ForegroundColor Cyan
        Write-Host "  /generate ... - Generate an image via Vertex AI. Prompts if prompt is missing." -ForegroundColor Cyan
        Write-Host "  /generate_from <path> - Describe image(s) at <path>, then generate new image(s). Prompts if path is missing." -ForegroundColor Cyan
        Write-Host "  /model [name] - Change the Gemini model. If no name, shows list." -ForegroundColor Cyan
        Write-Host "  /imagemodel [name] - Change the Vertex AI image generation model. If no name, shows list." -ForegroundColor Cyan
        Write-Host "  /exit         - Exit the chat session." -ForegroundColor Cyan
        Write-Host "  /help         - Show this command list." -ForegroundColor Cyan
        Write-Host "Enter your first prompt:" -F Cyan
    }
    try { return (Read-Host "`nYou") } catch { Write-Warning "Input error."; return "/exit" }
}

# --- Helper: Process API Result ---
function Process-ApiResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$ApiResult,
        [Parameter(Mandatory=$true)]$CurrentPromptInput,
        [Parameter(Mandatory=$true)]$SessionConfig,
        [Parameter(Mandatory=$true)]$ConversationHistory # Array
    )
    $updatedHistory = $ConversationHistory
    # --- DEBUGGING ---
    Write-Verbose "[Process-ApiResult] Received ApiResult object type: $($ApiResult.GetType().FullName)"
    Write-Verbose "[Process-ApiResult] ApiResult.Success value: $($ApiResult.Success) (Type: $($ApiResult.Success.GetType().FullName))"
    # --- END DEBUGGING ---
    # Explicitly check boolean value against $true
    if ($ApiResult -ne $null -and $ApiResult.PSObject.Properties['Success'] -ne $null -and $ApiResult.Success -eq $true) {
        Write-Host "`nGemini:" -F Green; Write-Host $ApiResult.GeneratedText -F Green; $updatedHistory = $ApiResult.UpdatedConversationHistory; Write-Verbose "History updated ($($updatedHistory.Count) turns)."
        if ($SessionConfig.OutputFile) { try { $turn = ($updatedHistory.Count / 2); "`n--- Turn $turn ($(Get-Date)) ---`nYou:`n$CurrentPromptInput`n`nGemini:`n$($ApiResult.GeneratedText)`n" | Out-File $SessionConfig.OutputFile -Append -Enc UTF8 -EA Stop; Write-Verbose "Appended turn." } catch { Write-Warning "Failed log append." } }
    } else { Write-Error "API call failed/skipped."; Write-Warning "History not updated."; if ($SessionConfig.OutputFile) { try { $turn = ($ConversationHistory.Count / 2) + 1; $errInfo=if($ApiResult){"Status:$($ApiResult.StatusCode) Err:$($ApiResult.ErrorRecord.Exception.Message) Body:$($ApiResult.ResponseBody)"}else{"N/A"}; "`n--- Turn $turn ($(Get-Date)) - API ERROR ---`nYou:`n$CurrentPromptInput`n`nERROR:`n$errInfo`n---" | Out-File $SessionConfig.OutputFile -Append -Enc UTF8 -EA Stop; Write-Verbose "Appended err log." } catch { Write-Warning "Failed err log append." } } }
    return $updatedHistory
}

# --- Helper: Ensure Vertex AI Config is Present (Prompts if needed) ---
function Ensure-VertexAiConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ref]$SessionConfigRef
    )
    $config = $SessionConfigRef.Value; $updated = $false
    if (-not ($config.VertexProjectId -and $config.VertexLocationId -and $config.VertexDefaultOutputFolder)) {
        Write-Warning "Vertex AI parameters required."; if(-not $config.VertexProjectId){$p=Read-Host "Enter GCP Project ID";if(-not $p){Write-Error "ID required.";return $false}$config.VertexProjectId=$p;$updated=$true}
        if(-not $config.VertexLocationId){$l=Read-Host "Enter Vertex Location (e.g., us-central1)";if(-not $l){Write-Error "Location required.";return $false}$config.VertexLocationId=$l;$updated=$true}
        if(-not $config.VertexDefaultOutputFolder){$o=Read-Host "Enter Vertex Output Folder";if(-not $o){Write-Error "Folder required.";return $false}try{if(-not(Test-Path -Lit $o -PathType Container)){Write-Warning "Creating $o";New-Item -Path $o -ItemType Directory -Force -EA Stop|Out-Null};$config.VertexDefaultOutputFolder=$o;$updated=$true}catch{Write-Error "Failed create folder '$o'.";return $false}}
        if ($updated) { $SessionConfigRef.Value = $config; Write-Host "Vertex AI config updated." -F Green }
    }
    return ($config.VertexProjectId -and $config.VertexLocationId -and $config.VertexDefaultOutputFolder)
}

# --- Helper: Prompt for Media Path (/media interactive) ---
function Prompt-ForMediaInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ref]$ImageFolderRef, [Parameter(Mandatory=$true)][ref]$VideoFolderRef,
        [Parameter(Mandatory=$true)][ref]$RecurseRef, [Parameter(Mandatory=$true)][ref]$InlineFilePathsRef
    )
    $raw = Read-Host "Enter Media Folder Path or File Path"; $added = $false
    if ($raw) { $input = $raw.Trim('"').Trim("'"); if (Test-Path -Lit $input -PathType Container) { $ImageFolderRef.Value=$input; $VideoFolderRef.Value=$input; Write-Host "(Folder: '$input')" -F Gray; $r=Read-Host "Recursive?(y/N)"; if($r -eq 'y'){$RecurseRef.Value=$true}; $added=$true } elseif (Test-Path -Lit $input -PathType Leaf) { $InlineFilePathsRef.Value=@($input); Write-Host "(File: $input)" -F Gray; $added=$true } else { Write-Warning "Path invalid: $input" } }
    return $added
}


# --- Helper: Handle Chat Commands ---
function Handle-ChatCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$TrimmedInput,
        [Parameter(Mandatory=$true)][ref]$SessionConfigRef,
        [Parameter(Mandatory=$true)][ref]$ConversationHistoryRef,
        [Parameter()]$LastApiResult, # Removed Mandatory
        [Parameter()]$LastUserPrompt, # Removed Mandatory
        [Parameter(Mandatory=$true)]$ApiKey,
        [Parameter(Mandatory=$true)][ref]$CurrentImageFolderRef, [Parameter(Mandatory=$true)][ref]$CurrentVideoFolderRef,
        [Parameter(Mandatory=$true)][ref]$CurrentRecurseRef, [Parameter(Mandatory=$true)][ref]$CurrentInlineFilePathsRef
    )
    # (Uses Ensure-VertexAiConfig, Prompt-ForMediaInput, Save-ChatToCsv, Start-VertexImageGeneration, Invoke-GeminiApi)
    $sessionConfig=$SessionConfigRef.Value;$conversationHistory=$ConversationHistoryRef.Value
    # Define Model Lists for Interactive Selection
    $geminiModelOptions = @('gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-1.5-flash-8b', 'gemini-2.0-flash', 'gemini-2.0-flash-exp-image-generation', 'gemini-2.0-flash-lite', 'gemini-2.5-pro-preview-03-25', 'gemini-2.5-flash-preview-04-17')
    $imagenModelOptions = @('imagen-3.0-generate-002', 'imagen-3.0-fast-generate-001', 'imagegeneration@006', 'imagegeneration@005')
    $cmdRes=@{CommandExecuted=$false;SkipApiCall=$false;ExitSession=$false;PromptOverride=$null;MediaAdded=$false}
    if(-not $TrimmedInput.StartsWith('/')){return $cmdRes}
    switch -Regex ($TrimmedInput){
        '^/(history|hist)$'{Write-Host "`n--- History ---"-F Yellow;if($conversationHistory.Count-eq 0){Write-Host "(Empty)"-F Gray}else{for($i=0;$i-lt $conversationHistory.Count;$i++){$t=$conversationHistory[$i];$r=$t.role.ToUpper();$txt=($t.parts|?{$_.text}|select -Exp text)-join "`n";$m=if($t.parts|?{$_.inline_data}){"(Inline)"}elseif($t.parts|?{$_.file_data}){"(FileAPI)"}else{""};Write-Host "[$r]$txt$m"-F (if($r-eq 'USER'){[ConsoleColor]::White}else{[ConsoleColor]::Green})}};Write-Host "---"-F Yellow;$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true}
        '^/clear$'{Write-Host "`nClearing history."-F Yellow;$ConversationHistoryRef.Value=@();$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true} # Note: Caller must clear last prompt/result if needed
        '^/retry$'{if($LastApiResult -and -not $LastApiResult.Success -and $LastUserPrompt){Write-Host "`nRetrying..."-F Yellow;Write-Host "Prompt: $LastUserPrompt"-F Gray;$cmdRes.PromptOverride=$LastUserPrompt;$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$false}else{Write-Warning "Nothing to retry.";$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true}}
        '^/config$'{Write-Host "`n--- Config ---"-F Yellow;$sessionConfig.GetEnumerator()|Sort Name|% { $val = if($_.Value -ne $null){($_.Value|Out-String -Stream).Trim()}else{"(null)"}; Write-Host ("{0,-25}: {1}"-f $_.Name,$val)};Write-Host "---"-F Yellow;$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true}
        '^/save$'{Write-Host "`nSaving history..."-F Yellow;if($sessionConfig.CsvOutputFile -and $conversationHistory.Count -gt 0){Save-ChatToCsv -ConversationHistory $conversationHistory -CsvOutputFile $sessionConfig.CsvOutputFile}elseif(-not $sessionConfig.CsvOutputFile){Write-Warning "No -CsvOutputFile."}else{Write-Warning "History empty."};$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true}
        '^/exit$'{Write-Host Exiting. -F Cyan;$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true;$cmdRes.ExitSession=$true}
        '^/media(\s+(.+))?$'{$CurrentImageFolderRef.Value=$null;$CurrentVideoFolderRef.Value=$null;$CurrentRecurseRef.Value=$false;$CurrentInlineFilePathsRef.Value=$null;$mediaPath=$null;$added=$false;if($Matches[2]){$mediaPath=$Matches[2].Trim('"').Trim("'");Write-Host "`nMedia from command: '$mediaPath'"-F Yellow;if(Test-Path -Lit $mediaPath -PathType Container){$CurrentImageFolderRef.Value=$mediaPath;$CurrentVideoFolderRef.Value=$mediaPath;Write-Host "(Folder)"-F Gray;$r=Read-Host "Recursive?(y/N)";if($r -eq 'y'){$CurrentRecurseRef.Value=$true};$added=$true}elseif(Test-Path -Lit $mediaPath -PathType Leaf){$CurrentInlineFilePathsRef.Value=@($mediaPath);Write-Host "(File)"-F Gray;$added=$true}else{Write-Warning "Invalid path."}}else{Write-Host "`nAdding media..."-F Yellow;$added=Prompt-ForMediaInput -ImageFolderRef $CurrentImageFolderRef -VideoFolderRef $CurrentVideoFolderRef -RecurseRef $CurrentRecurseRef -InlineFilePathsRef $CurrentInlineFilePathsRef}
            if($added){$cmdRes.MediaAdded=$true;$prompt=Read-Host " You (prompt for media)";$cmdRes.PromptOverride=$prompt;$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$false}else{$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true}}
        '^/model(\s+(\S+))?$' {
            $cur = $sessionConfig.Model; Write-Host "`nCurrent Gemini Model: '$cur'" -F Gray
            if ($Matches[2]) { $new = $Matches[2].Trim(); $sessionConfig.Model = $new; Write-Host "Model -> '$new'" -F Yellow }
            else {
                Write-Host "Available Gemini models:" -F Cyan
                for ($i = 0; $i -lt $geminiModelOptions.Count; $i++) { Write-Host ("  {0}. {1}" -f ($i + 1), $geminiModelOptions[$i]) -F Cyan }
                $inp = Read-Host "Enter number or custom name"
                if ($inp -match '^\d+$' -and [int]$inp -ge 1 -and [int]$inp -le $geminiModelOptions.Count) { $sessionConfig.Model = $geminiModelOptions[[int]$inp - 1] }
                elseif ($inp) { $sessionConfig.Model = $inp.Trim() }
                else { Write-Warning "No change."; $inp = $null }
                if ($inp) { Write-Host "Model -> '$($sessionConfig.Model)'" -F Yellow }
            }
            $SessionConfigRef.Value = $sessionConfig; $cmdRes.CommandExecuted = $true; $cmdRes.SkipApiCall = $true
        }
        '^/imagemodel(\s+(\S+))?$' {
            if (-not (Ensure-VertexAiConfig -SessionConfigRef $SessionConfigRef)) { $cmdRes.CommandExecuted = $true; $cmdRes.SkipApiCall = $true; return $cmdRes }
            $sessionConfig = $SessionConfigRef.Value; $cur = $sessionConfig.VertexImageModel; Write-Host "`nCurrent Vertex Model: '$cur'" -F Gray
            if ($Matches[2]) { $new = $Matches[2].Trim(); $sessionConfig.VertexImageModel = $new; Write-Host "Vertex Model -> '$new'" -F Yellow }
            else {
                Write-Host "Available Vertex Imagen models:" -F Cyan
                for ($i = 0; $i -lt $imagenModelOptions.Count; $i++) { Write-Host ("  {0}. {1}" -f ($i + 1), $imagenModelOptions[$i]) -F Cyan }
                $inp = Read-Host "Enter number or custom name"
                if ($inp -match '^\d+$' -and [int]$inp -ge 1 -and [int]$inp -le $imagenModelOptions.Count) { $sessionConfig.VertexImageModel = $imagenModelOptions[[int]$inp - 1] }
                elseif ($inp) { $sessionConfig.VertexImageModel = $inp.Trim() }
                else { Write-Warning "No change."; $inp = $null }
                if ($inp) { Write-Host "Vertex Model -> '$($sessionConfig.VertexImageModel)'" -F Yellow }
            }
            $SessionConfigRef.Value = $sessionConfig; $cmdRes.CommandExecuted = $true; $cmdRes.SkipApiCall = $true
        }
        '/(generate|image)(\s+(.+))?$' { # Prompt optional
            $cmd=$Matches[1]; if(-not(Ensure-VertexAiConfig -Ses $SessionConfigRef)){$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true;return $cmdRes}; $sessionConfig=$SessionConfigRef.Value;
            $prompt = $null; if($Matches[3]){$prompt=$Matches[3].Trim()}else{$prompt=Read-Host "Enter prompt for /$cmd";if(-not $prompt){Write-Warning "Prompt empty.";$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true;return $cmdRes}}
            Write-Host "/$cmd command detected"-F Magenta;Write-Host "Prompt: $prompt"-F Magenta;$vParams=@{ProjectId=$sessionConfig.VertexProjectId;LocationId=$sessionConfig.VertexLocationId;Prompt=$prompt;OutputFolder=$sessionConfig.VertexDefaultOutputFolder;ModelId=$sessionConfig.VertexImageModel};if($sessionConfig.Verbose){$vParams.Verbose=$true};Start-VertexImageGeneration @vParams;$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true
        }
        '^/generate_from(\s+(.+))?$' { # Path optional
            if(-not(Ensure-VertexAiConfig -Ses $SessionConfigRef)){$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true;return $cmdRes}; $sessionConfig=$SessionConfigRef.Value;
            $inpPath=$null; if($Matches[2]){$inpPath=$Matches[2].Trim('"').Trim("'")}else{$inpPath=Read-Host "Enter source path for /generate_from";if(-not $inpPath){Write-Warning "Path empty.";$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true;return $cmdRes};$inpPath=$inpPath.Trim('"').Trim("'")}
            $srcPaths=[System.Collections.ArrayList]::new();if(Test-Path -Lit $inpPath -PathType Leaf){[void]$srcPaths.Add($inpPath);Write-Host "`n--- Gen From File: '$inpPath' ---"-F Yellow}elseif(Test-Path -Lit $inpPath -PathType Container){$imgExt=@('.jpg','.jpeg','.png','.webp','.gif','.heic','.heif','.bmp','.tif','.tiff');$found=Get-ChildItem -Lit $inpPath -File|?{$imgExt -contains $_.Extension.ToLowerInvariant()};if($found){$found|%{[void]$srcPaths.Add($_.FullName)};Write-Host "`n--- Gen From Folder: '$inpPath' ($($found.Count) images) ---"-F Yellow}else{Write-Error "No images in '$inpPath'."}}else{Write-Error "Path invalid: '$inpPath'"}
            if($srcPaths.Count -eq 0){$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true;return $cmdRes};$idx=0;foreach($curPath in $srcPaths){$idx++;Write-Host "`nProcessing image $idx/$($srcPaths.Count): '$curPath'"-F Cyan;$descPrompt="Describe image vividly for AI generation.";Write-Host "Asking Gemini..."-F DarkGray;$dParams=@{ApiKey=$ApiKey;Model=$sessionConfig.Model;Prompt=$descPrompt;InlineFilePaths=@($curPath);ConversationHistory=@();TimeoutSec=$sessionConfig.TimeoutSec};if($sessionConfig.GenConfig){$dParams.GenerationConfig=$sessionConfig.GenConfig};$dRes=Invoke-GeminiApi @dParams;if(-not $dRes.Success){Write-Error "Failed get desc for '$curPath'.";continue};$gDesc=$dRes.GeneratedText;Write-Host "Gemini Desc:"-F Green;Write-Host $gDesc -F Green;Write-Host "`nGenerating from desc..."-F Yellow;$vParams=@{ProjectId=$sessionConfig.VertexProjectId;LocationId=$sessionConfig.VertexLocationId;Prompt=$gDesc;OutputFolder=$sessionConfig.VertexDefaultOutputFolder;ModelId=$sessionConfig.VertexImageModel};if($sessionConfig.Verbose){$vParams.Verbose=$true};Start-VertexImageGeneration @vParams;if($sessionConfig.FileDelaySec -gt 0 -and $idx -lt $srcPaths.Count){Start-Sleep -Sec $sessionConfig.FileDelaySec}};$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true}
        '^/help$' {
            # Display Help Text (Copied from Get-ChatInput initial display)
            Write-Host "`n--- Available Commands ---" -ForegroundColor Yellow
            Write-Host "  /history      - Display conversation history." -ForegroundColor Cyan
            Write-Host "  /clear        - Clear conversation history." -ForegroundColor Cyan
            Write-Host "  /retry        - Retry the last failed API call." -ForegroundColor Cyan
            Write-Host "  /config       - Show current session settings." -ForegroundColor Cyan
            Write-Host "  /save         - Save history to CSV (if -CsvOutputFile specified)." -ForegroundColor Cyan
            Write-Host "  /media [path] - Add media (folder/file) for the next prompt. If no path, prompts interactively." -ForegroundColor Cyan
            Write-Host "  /generate ... - Generate an image via Vertex AI. Prompts if prompt is missing." -ForegroundColor Cyan
            Write-Host "  /generate_from <path> - Describe image(s) at <path>, then generate new image(s). Prompts if path is missing." -ForegroundColor Cyan
            Write-Host "  /model [name] - Change the Gemini model. If no name, shows list." -ForegroundColor Cyan
            Write-Host "  /imagemodel [name] - Change the Vertex AI image generation model. If no name, shows list." -ForegroundColor Cyan
            Write-Host "  /exit         - Exit the chat session." -ForegroundColor Cyan
            Write-Host "  /help         - Show this command list." -ForegroundColor Cyan
            $cmdRes.CommandExecuted = $true; $cmdRes.SkipApiCall = $true
        }
        default{Write-Warning "Unrecognized command: '$TrimmedInput'. Type '/help' for options.";$cmdRes.CommandExecuted=$false;$cmdRes.SkipApiCall=$true} # Don't execute, but skip API call
    }
    return $cmdRes
}

Write-Verbose "ChatUtils.ps1 loaded."
