# ChatUtils.ps1
# Contains functions supporting the interactive chat loop, command handling,
# user input, API result processing, and Vertex AI configuration checks.

#Requires -Version 7

# Depends on CoreUtils.ps1, GeminiApiUtils.ps1, VertexApiUtils.ps1, FileProcessingUtils.ps1

# --- Script Scope Variables ---
# Define Model Lists for Interactive Selection globally within this script
$Script:imagenModelOptions = @('imagen-3.0-generate-002', 'imagen-3.0-fast-generate-001', 'imagegeneration@006', 'imagegeneration@005')

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
        Write-Host "  /back         - Cancel current input/selection prompt." -ForegroundColor Cyan
        Write-Host "  /help         - Show this command list." -ForegroundColor Cyan
        Write-Host "Enter your first prompt:" -F Cyan
    }
    # Loop until valid input (not /back) or error occurs
    while ($true) {
        try {
            $userInput = Read-Host "`nYou"
            if ($userInput.Trim().ToLowerInvariant() -eq '/back') {
                Write-Host "(Input cancelled)" -ForegroundColor Gray
                continue # Ask for input again
            }
            if ([string]::IsNullOrWhiteSpace($userInput)) {
                Write-Warning "Input cannot be empty. Please enter a prompt or command (e.g., /help, /exit)."
                continue # Ask for input again
            }
            return $userInput # Return valid input
        } catch { Write-Warning "Input error."; return "/exit" } # Exit on Read-Host error
    }
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
    # Explicitly check boolean value against $true
    if ($ApiResult -ne $null -and $ApiResult.PSObject.Properties['Success'] -ne $null -and $ApiResult.Success -eq $true) {
        Write-Host "`nGemini:" -F Green; Write-Host $ApiResult.GeneratedText -F Green; $updatedHistory = $ApiResult.UpdatedConversationHistory; Write-Verbose "History updated ($($updatedHistory.Count) turns)." # Log successful interactive turn
        if ($SessionConfig.LogFile) { try { $turn = ($updatedHistory.Count / 2); "`n--- Turn $turn ($(Get-Date)) ---`nYou:`n$CurrentPromptInput`n`nGemini:`n$($ApiResult.GeneratedText)`n" | Out-File $SessionConfig.LogFile -Append -Enc UTF8 -EA Stop; Write-Verbose "Appended turn to LogFile." } catch { Write-Warning "Failed append to LogFile." } }
    } else { Write-Error "API call failed/skipped."; Write-Warning "History not updated."; if ($SessionConfig.LogFile) { try { $turn = ($ConversationHistory.Count / 2) + 1; $errInfo=if($ApiResult){"Status:$($ApiResult.StatusCode) Err:$($ApiResult.ErrorRecord.Exception.Message) Body:$($ApiResult.ResponseBody)"}else{"N/A"}; "`n--- Turn $turn ($(Get-Date)) - API ERROR ---`nYou:`n$CurrentPromptInput`n`nERROR:`n$errInfo`n---" | Out-File $SessionConfig.LogFile -Append -Enc UTF8 -EA Stop; Write-Verbose "Appended error to LogFile." } catch { Write-Warning "Failed append error to LogFile." } } }
    return $updatedHistory
}

# --- Helper: Ensure Vertex AI Config is Present (Prompts if needed) ---
function Ensure-VertexAiConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ref]$SessionConfigRef
    )
    $config = $SessionConfigRef.Value; $updated = $false
    if (-not ($config.VertexProjectId -and $config.VertexLocationId -and $config.VertexDefaultOutputFolder -and $config.VertexImageModel)) { # Add check for VertexImageModel
        Write-Warning "Vertex AI parameters required."
        # Loop for Project ID
        if(-not $config.VertexProjectId){
            while ($true) {
                $p = Read-Host "Enter GCP Project ID (or /back to cancel)"
                if ($p.Trim().ToLowerInvariant() -eq '/back') { Write-Host "(Input cancelled)" -F Gray; return $false }
                if (-not ([string]::IsNullOrWhiteSpace($p))) { $config.VertexProjectId = $p.Trim(); $updated = $true; break }
                Write-Warning "Project ID cannot be empty. Please try again."
            }
        }
        # Loop for Location ID
        if(-not $config.VertexLocationId){
            while ($true) {
                $l = Read-Host "Enter Vertex Location (e.g., us-central1, or /back to cancel)"
                if ($l.Trim().ToLowerInvariant() -eq '/back') { Write-Host "(Input cancelled)" -F Gray; return $false }
                if (-not ([string]::IsNullOrWhiteSpace($l))) { $config.VertexLocationId = $l.Trim(); $updated = $true; break }
                Write-Warning "Location ID cannot be empty. Please try again."
            }
        }
        # Loop for Output Folder
        if(-not $config.VertexDefaultOutputFolder){
            while ($true) {
                $o = Read-Host "Enter Vertex Output Folder (or /back to cancel)"
                if ($o.Trim().ToLowerInvariant() -eq '/back') { Write-Host "(Input cancelled)" -F Gray; return $false }
                if (-not ([string]::IsNullOrWhiteSpace($o))) { break } # Exit loop if input is not empty
                Write-Warning "Output Folder path cannot be empty. Please try again."
            }
            # Proceed with validation/creation using the non-empty $o
            if(-not $o){Write-Error "Folder path required.";return $false}
            try{if(-not(Test-Path -Lit $o -PathType Container)){Write-Warning "Creating $o";New-Item -Path $o -ItemType Directory -Force -EA Stop|Out-Null};$config.VertexDefaultOutputFolder=$o;$updated=$true}
            catch{Write-Error "Failed create folder '$o'.";return $false}
        }
        # Loop for Image Model
        if(-not $config.VertexImageModel){
             Write-Host "Available Vertex Imagen models:" -F Cyan
             for ($i = 0; $i -lt $Script:imagenModelOptions.Count; $i++) { Write-Host ("  {0}. {1}" -f ($i + 1), $Script:imagenModelOptions[$i]) -F Cyan }
             while ($true) {
                $inp = Read-Host "Enter Vertex Image Model number or custom name (or /back to cancel)"
                if ($inp.Trim().ToLowerInvariant() -eq '/back') { Write-Host "(Input cancelled)" -F Gray; return $false }
                if ($inp -match '^\d+$' -and [int]$inp -ge 1 -and [int]$inp -le $Script:imagenModelOptions.Count) { $config.VertexImageModel = $Script:imagenModelOptions[[int]$inp - 1]; $updated = $true; break }
                elseif (-not [string]::IsNullOrWhiteSpace($inp)) { $config.VertexImageModel = $inp.Trim(); $updated = $true; break }
                Write-Warning "Invalid selection or empty input. Please try again."
             }
             Write-Host "Vertex Model -> '$($config.VertexImageModel)'" -F Yellow
        }

        if ($updated) { $SessionConfigRef.Value = $config; Write-Host "Vertex AI config updated." -F Green }
    }
    # Return true only if ALL required parameters are now present
    return ($config.VertexProjectId -and $config.VertexLocationId -and $config.VertexDefaultOutputFolder -and $config.VertexImageModel)
}

# --- Helper: Prompt for Media Path (/media interactive) ---
function Prompt-ForMediaInput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][ref]$ImageFolderRef, [Parameter(Mandatory=$true)][ref]$VideoFolderRef,
        [Parameter(Mandatory=$true)][ref]$RecurseRef, [Parameter(Mandatory=$true)][ref]$InlineFilePathsRef
    )
    $raw = Read-Host "Enter Media Folder Path or File Path"; $added = $false
    # Loop for Path Input
    while ($true) {
        $raw = Read-Host "Enter Media Folder Path or File Path (or /back to cancel)"
        if ($raw.Trim().ToLowerInvariant() -eq '/back') { Write-Host "(Input cancelled)" -F Gray; return $false }
        if (-not ([string]::IsNullOrWhiteSpace($raw))) { break }
        Write-Warning "Path cannot be empty. Please try again."
    }

    if ($raw.Trim().ToLowerInvariant() -eq '/back') { Write-Host "(Input cancelled)" -F Gray; return $false } # Handle /back

    if ($raw) {
        $input = $raw.Trim('"').Trim("'")
        if (Test-Path -Lit $input -PathType Container) { $ImageFolderRef.Value=$input; $VideoFolderRef.Value=$input; Write-Host "(Folder: '$input')" -F Gray;
            $r = '' # Initialize
            # Loop for Recursion Input
            while ($true) {
                $r = Read-Host "Search recursively? (Y/n, or /back to cancel)" # Changed prompt
                $trimmedLowerR = $r.Trim().ToLowerInvariant()
                if ($trimmedLowerR -eq '/back') {
                    Write-Host "(Input cancelled)" -F Gray
                    return $false # Cancel the whole Prompt-ForMediaInput
                }
                if ([string]::IsNullOrWhiteSpace($trimmedLowerR) -or $trimmedLowerR -eq 'y' -or $trimmedLowerR -eq 'n') {
                    break # Valid input
                }
                Write-Warning "Invalid input. Please enter 'y', 'n', or /back."
            }
            if ([string]::IsNullOrWhiteSpace($r) -or $r.Trim().ToLowerInvariant() -eq 'y') { # Default empty to 'y'
                $RecurseRef.Value = $true
            } # else $RecurseRef.Value remains $false (default for 'n')
            $added = $true
        }
        elseif (Test-Path -Lit $input -PathType Leaf) { $InlineFilePathsRef.Value=@($input); Write-Host "(File: $input)" -F Gray; $added=$true } else { Write-Warning "Path invalid: $input" } }
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
        [Parameter(Mandatory=$true)][ref]$CurrentRecurseRef, [Parameter(Mandatory=$true)][ref]$CurrentInlineFilePathsRef,
        [Parameter()][bool]$IsVerbose = $false # Explicitly pass verbose status, make non-mandatory
    )
    $sessionConfig=$SessionConfigRef.Value;$conversationHistory=$ConversationHistoryRef.Value
    # Define Gemini Model List (Imagen list moved to script scope)
    $geminiModelOptions = @('gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-1.5-flash-8b', 'gemini-2.0-flash', 'gemini-2.0-flash-exp-image-generation', 'gemini-2.0-flash-lite', 'gemini-2.5-pro-preview-03-25', 'gemini-2.5-flash-preview-04-17')
    # $imagenModelOptions defined at script scope
    $cmdRes=@{CommandExecuted=$false;SkipApiCall=$false;ExitSession=$false;PromptOverride=$null;MediaAdded=$false}
    if(-not $TrimmedInput.StartsWith('/')){return $cmdRes}
    switch -Regex ($TrimmedInput){
        '^/(history|hist)$'{Write-Host "`n--- History ---"-F Yellow;if($conversationHistory.Count-eq 0){Write-Host "(Empty)"-F Gray}else{for($i=0;$i-lt $conversationHistory.Count;$i++){$t=$conversationHistory[$i];$r=$t.role.ToUpper();$txt=($t.parts|?{$_.text}|select -Exp text)-join "`n";$m=if($t.parts|?{$_.inline_data}){"(Inline)"}elseif($t.parts|?{$_.file_data}){"(FileAPI)"}else{""};Write-Host "[$r]$txt$m"-F (if($r-eq 'USER'){[ConsoleColor]::White}else{[ConsoleColor]::Green})}};Write-Host "---"-F Yellow;$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true}
        '^/clear$'{Write-Host "`nClearing history."-F Yellow;$ConversationHistoryRef.Value=@();$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true} # Note: Caller must clear last prompt/result if needed
        '^/retry$'{if($LastApiResult -and -not $LastApiResult.Success -and $LastUserPrompt){Write-Host "`nRetrying..."-F Yellow;Write-Host "Prompt: $LastUserPrompt"-F Gray;$cmdRes.PromptOverride=$LastUserPrompt;$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$false}else{Write-Warning "Nothing to retry.";$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true}}
        '^/config$'{Write-Host "`n--- Config ---"-F Yellow;$sessionConfig.GetEnumerator()|Sort Name|% { $val = if($_.Value -ne $null){($_.Value|Out-String -Stream).Trim()}else{"(null)"}; Write-Host ("{0,-25}: {1}"-f $_.Name,$val)};Write-Host "---"-F Yellow;$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true}
        '^/save$'{Write-Host "`nSaving history..."-F Yellow;if($sessionConfig.CsvOutputFile -and $conversationHistory.Count -gt 0){Save-ChatToCsv -ConversationHistory $conversationHistory -CsvOutputFile $sessionConfig.CsvOutputFile}elseif(-not $sessionConfig.CsvOutputFile){Write-Warning "No -CsvOutputFile."}else{Write-Warning "History empty."};$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true}
        '^/exit$'{Write-Host Exiting. -F Cyan;$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true;$cmdRes.ExitSession=$true}
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
                    # Loop for Recursion Input
                    $r = '' # Initialize
                    while ($true) {
                        $r = Read-Host "Search recursively? (Y/n, or /back to cancel)" # Changed prompt
                        $trimmedLowerR = $r.Trim().ToLowerInvariant()
                        if ($trimmedLowerR -eq '/back') {
                            Write-Host "(Input cancelled)" -F Gray
                            $mediaAddedSuccessfully = $false # Signal cancellation
                            break
                        }
                        if ([string]::IsNullOrWhiteSpace($trimmedLowerR) -or $trimmedLowerR -eq 'y' -or $trimmedLowerR -eq 'n') {
                            break # Valid input
                        }
                        Write-Warning "Invalid input. Please enter 'y', 'n', or /back."
                    }

                    if ($mediaAddedSuccessfully -ne $false) { # If not cancelled
                        if ([string]::IsNullOrWhiteSpace($r) -or $r.Trim().ToLowerInvariant() -eq 'y') { # Default empty to 'y'
                            $CurrentRecurseRef.Value = $true
                        } # else $CurrentRecurseRef.Value remains $false (default for 'n')
                        $mediaAddedSuccessfully = $true # Confirm successful processing up to this point
                    }
                } elseif (Test-Path -LiteralPath $mediaPathProvided -PathType Leaf) {
                    $CurrentInlineFilePathsRef.Value = @($mediaPathProvided); Write-Host "(Will use file: $mediaPathProvided)" -ForegroundColor Gray
                    $mediaAddedSuccessfully = $true
                } else { Write-Warning "Media path provided not found or invalid: '$mediaPathProvided'" }
            } else { # Interactive prompt
                # Check if an initial media path was provided to the session
                $initialMediaPath = $sessionConfig.Media # Changed from InitialMedia
                # Use Write-Host conditional on the explicitly passed $IsVerbose for reliable output
                if ($IsVerbose) { Write-Host "[DEBUG /media] Media from config: '$initialMediaPath'" -ForegroundColor DarkGray }
                $useInitial = $false
                $initialPathExists = $false
                if (-not [string]::IsNullOrWhiteSpace($initialMediaPath)) { $initialPathExists = Test-Path -LiteralPath $initialMediaPath -ErrorAction SilentlyContinue }
                # Use Write-Host conditional on the explicitly passed $IsVerbose for reliable output
                if ($IsVerbose) { Write-Host "[DEBUG /media] Initial path exists: $initialPathExists" -ForegroundColor DarkGray }

                if ($initialPathExists) {
                    $promptMsg = "Use initial media path '$initialMediaPath'? (Y/n)"
                    $responseToInitialPrompt = '' # Stores 'y', 'n', or empty
                    $initialPromptCancelled = $false
                    # Loop for Confirmation
                    while ($true) {
                        $userInputForInitial = Read-Host "$promptMsg (or /back to cancel)"
                        $trimmedLowerResponse = $userInputForInitial.Trim().ToLowerInvariant()
                        if ($trimmedLowerResponse -eq '/back') {
                            Write-Host "(Input cancelled)" -F Gray
                            $useInitial = $false
                            $initialPromptCancelled = $true
                            break
                        }
                        if ([string]::IsNullOrWhiteSpace($trimmedLowerResponse) -or $trimmedLowerResponse -eq 'y' -or $trimmedLowerResponse -eq 'n') {
                            $responseToInitialPrompt = $trimmedLowerResponse # Store the valid response
                            break
                        }
                        Write-Warning "Invalid input. Please enter 'y', 'n', or /back."
                    }

                    if (-not $initialPromptCancelled) {
                        if ([string]::IsNullOrWhiteSpace($responseToInitialPrompt) -or $responseToInitialPrompt -ne 'n') { # User chose 'y' or pressed Enter
                            $useInitial = $true
                            # Set refs based on initial path type
                            if (Test-Path -LiteralPath $initialMediaPath -PathType Container) {
                                $CurrentImageFolderRef.Value = $initialMediaPath; $CurrentVideoFolderRef.Value = $initialMediaPath
                                Write-Host "(Using initial folder: '$initialMediaPath')" -ForegroundColor Gray
                                # Loop for Recursion Input (nested)
                                $r = '' # Initialize
                                $recursivePromptCancelled = $false
                                while ($true) {
                                    $r = Read-Host "Search recursively? (Y/n, or /back to cancel)" # Changed prompt
                                    $trimmedLowerR = $r.Trim().ToLowerInvariant()
                                    if ($trimmedLowerR -eq '/back') {
                                        Write-Host "(Input cancelled)" -F Gray
                                        $recursivePromptCancelled = $true
                                        break
                                    }
                                    if ([string]::IsNullOrWhiteSpace($trimmedLowerR) -or $trimmedLowerR -eq 'y' -or $trimmedLowerR -eq 'n') {
                                        break # Valid input
                                    }
                                    Write-Warning "Invalid input. Please enter 'y', 'n', or /back."
                                }
                                if (-not $recursivePromptCancelled) {
                                    if ([string]::IsNullOrWhiteSpace($r) -or $r.Trim().ToLowerInvariant() -eq 'y') { # Default empty to 'y'
                                        $CurrentRecurseRef.Value = $true
                                    }
                                    $mediaAddedSuccessfully = $true # Success for this path
                                } else {
                                    $mediaAddedSuccessfully = $false # Cancelled
                                }
                            } else { # Assume Leaf
                                $CurrentInlineFilePathsRef.Value = @($initialMediaPath); Write-Host "(Using initial file: $initialMediaPath)" -ForegroundColor Gray
                                $mediaAddedSuccessfully = $true # Success for this path
                            }
                        } else { # User chose 'n' to not use initial path
                            $useInitial = $false # $mediaAddedSuccessfully remains false from its initial state
                        }
                    } else { # Initial prompt was cancelled
                        $mediaAddedSuccessfully = $false # Ensure overall failure
                    }
                }
                # If no valid initial path existed, or user chose 'n'
                # OR if initial path processing was cancelled or failed
                if (-not $useInitial -and (-not $mediaAddedSuccessfully)) {
                    Write-Host "`nEnter new media path..." -ForegroundColor Yellow # Consistent verb
                    # Clear existing refs before prompting for new ones
                    $CurrentImageFolderRef.Value = $null; $CurrentVideoFolderRef.Value = $null; $CurrentRecurseRef.Value = $false; $CurrentInlineFilePathsRef.Value = $null
                    $mediaAddedSuccessfully = Prompt-ForMediaInput -ImageFolderRef $CurrentImageFolderRef -VideoFolderRef $CurrentVideoFolderRef -RecurseRef $CurrentRecurseRef -InlineFilePathsRef $CurrentInlineFilePathsRef
                }
            }

            if ($mediaAddedSuccessfully) {
                $cmdRes.MediaAdded = $true # Signal that media was added
                Write-Host "Media added. Enter the text prompt associated with this media:" -ForegroundColor Cyan
                $promptForMediaText = $null
                $associatedPromptCancelled = $false
                # Loop for Associated Prompt
                while ($true) {
                    $userInputForMediaPrompt = Read-Host " You (prompt for media, or /back to cancel)"
                    if ($userInputForMediaPrompt.Trim().ToLowerInvariant() -eq '/back') {
                        Write-Host "(Input cancelled)" -F Gray
                        $associatedPromptCancelled = $true
                        break
                    }
                    if (-not ([string]::IsNullOrWhiteSpace($userInputForMediaPrompt))) {
                        $promptForMediaText = $userInputForMediaPrompt
                        break
                    }
                    Write-Warning "Prompt cannot be empty. Please try again."
                }
                if (-not $associatedPromptCancelled) {
                    $cmdRes.PromptOverride = $promptForMediaText # Tell main loop to use this prompt
                    $cmdRes.CommandExecuted = $true; $cmdRes.SkipApiCall = $false # Allow API call with this media/prompt
                } else {
                    $mediaAddedSuccessfully = $false # Mark overall media addition as failed
                    $cmdRes.CommandExecuted = $true; $cmdRes.SkipApiCall = $true
                }
            }
            # If, after all attempts, media was not successfully added (or was cancelled)
            if (-not $mediaAddedSuccessfully) {
                $cmdRes.MediaAdded = $false # Ensure this is false
                $cmdRes.CommandExecuted = $true # Command was processed (attempted)
                $cmdRes.SkipApiCall = $true   # But skip API call as media part failed
            }
        }
        '^/model(\s+(\S+))?$' {
            $cur = $sessionConfig.Model; Write-Host "`nCurrent Gemini Model: '$cur'" -F Gray
            if ($Matches[2]) { $new = $Matches[2].Trim(); $sessionConfig.Model = $new; Write-Host "Model -> '$new'" -F Yellow }
            else {
                Write-Host "Available Gemini models:" -F Cyan
                for ($i = 0; $i -lt $geminiModelOptions.Count; $i++) { Write-Host ("  {0}. {1}" -f ($i + 1), $geminiModelOptions[$i]) -F Cyan }
                # Loop for Model Selection
                while ($true) {
                    $inp = Read-Host "Enter number or custom name (or /back to cancel)" # Prompt is inside the loop
                    if ($inp.Trim().ToLowerInvariant() -eq '/back') {
                        Write-Host "(Selection cancelled)" -F Gray
                        $inp = $null
                        $cmdRes.CommandExecuted=$true; $cmdRes.SkipApiCall=$true # Set flags before returning
                        return $cmdRes
                    }
                    if (-not ([string]::IsNullOrWhiteSpace($inp))) { break } # Allow numeric or custom name
                    Write-Warning "Input cannot be empty. Please try again."
                }
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
                for ($i = 0; $i -lt $Script:imagenModelOptions.Count; $i++) { Write-Host ("  {0}. {1}" -f ($i + 1), $Script:imagenModelOptions[$i]) -F Cyan } # Use script scope variable
                # Loop for Image Model Selection
                while ($true) {
                    $inp = Read-Host "Enter number or custom name (or /back to cancel)"
                    if ($inp.Trim().ToLowerInvariant() -eq '/back') {
                        Write-Host "(Selection cancelled)" -F Gray
                        $inp = $null
                        $cmdRes.CommandExecuted=$true; $cmdRes.SkipApiCall=$true # Set flags before returning
                        return $cmdRes
                    }
                    if (-not ([string]::IsNullOrWhiteSpace($inp))) { break } # Allow numeric or custom name
                    Write-Warning "Input cannot be empty. Please try again."
                }
                if ($inp -match '^\d+$' -and [int]$inp -ge 1 -and [int]$inp -le $Script:imagenModelOptions.Count) { $sessionConfig.VertexImageModel = $Script:imagenModelOptions[[int]$inp - 1] } # Use script scope variable
                elseif (-not [string]::IsNullOrWhiteSpace($inp)) { $sessionConfig.VertexImageModel = $inp.Trim() } # Check for non-empty input before setting
                else { Write-Warning "No change."; $inp = $null }
                if ($inp) { Write-Host "Vertex Model -> '$($sessionConfig.VertexImageModel)'" -F Yellow }
            }
            $SessionConfigRef.Value = $sessionConfig; $cmdRes.CommandExecuted = $true; $cmdRes.SkipApiCall = $true
        }
        '/(generate|image)(\s+(.+))?$' { # Prompt is optional
            $cmd=$Matches[1]; if(-not(Ensure-VertexAiConfig -Ses $SessionConfigRef)){$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true;return $cmdRes}; $sessionConfig=$SessionConfigRef.Value;
            $prompt = $null;
            # Check if prompt was provided in the command ($Matches[3] corresponds to the (.+) part)
            if($Matches[3]){$prompt=$Matches[3].Trim()}
            else{
                # Loop for Generate Prompt
                while ($true) {
                    $prompt = Read-Host "Enter prompt for /$cmd (or /back to cancel)"
                    if ($prompt.Trim().ToLowerInvariant() -eq '/back') {
                        Write-Host "(Input cancelled)" -F Gray
                        $prompt = $null
                        $cmdRes.CommandExecuted=$true; $cmdRes.SkipApiCall=$true # Set flags before returning
                        return $cmdRes
                    }
                    if (-not ([string]::IsNullOrWhiteSpace($prompt))) { break }
                    Write-Warning "Prompt cannot be empty. Please try again."
                }
                if(-not $prompt){Write-Warning "Prompt empty. Command cancelled.";$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true;return $cmdRes}
            }

            Write-Host "/$cmd command detected"-F Magenta;Write-Host "Prompt: $prompt"-F Magenta;
            $vParams=@{ProjectId=$sessionConfig.VertexProjectId;LocationId=$sessionConfig.VertexLocationId;Prompt=$prompt;OutputFolder=$sessionConfig.VertexDefaultOutputFolder;ModelId=$sessionConfig.VertexImageModel};
            if($IsVerbose){$vParams.Verbose=$true};
            # Call the function and discard any return value to prevent it from printing to console
            Start-VertexImageGeneration @vParams | Out-Null;
            $cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true
        }
        '^/generate_from(\s+(.+))?$' { # Path is optional
            if(-not(Ensure-VertexAiConfig -Ses $SessionConfigRef)){$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true;return $cmdRes}; $sessionConfig=$SessionConfigRef.Value;
            $inpPath=$null;
            # Loop for Generate_From Path
            if($Matches[2]){$inpPath=$Matches[2].Trim('"').Trim("'")}
            else {
                while ($true) {
                    $inpPath = Read-Host "Enter source path for /generate_from (or /back to cancel)"
                    if ($inpPath.Trim().ToLowerInvariant() -eq '/back') {
                        Write-Host "(Input cancelled)" -F Gray
                        $inpPath = $null
                        $cmdRes.CommandExecuted=$true; $cmdRes.SkipApiCall=$true # Set flags before returning
                        return $cmdRes
                    }
                    if (-not ([string]::IsNullOrWhiteSpace($inpPath))) { break }
                    Write-Warning "Path cannot be empty. Please try again."
                }
            }
            if (-not $inpPath) { Write-Warning "Path empty."; $cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true;return $cmdRes } # Should not happen with loop, but safety check
            $inpPath=$inpPath.Trim('"').Trim("'")

            $srcPaths=[System.Collections.ArrayList]::new();if(Test-Path -Lit $inpPath -PathType Leaf){[void]$srcPaths.Add($inpPath);Write-Host "`n--- Gen From File: '$inpPath' ---"-F Yellow}elseif(Test-Path -Lit $inpPath -PathType Container){$imgExt=@('.jpg','.jpeg','.png','.webp','.gif','.heic','.heif','.bmp','.tif','.tiff');$found=Get-ChildItem -Lit $inpPath -File|?{$imgExt -contains $_.Extension.ToLowerInvariant()};if($found){$found|%{[void]$srcPaths.Add($_.FullName)};Write-Host "`n--- Gen From Folder: '$inpPath' ($($found.Count) images) ---"-F Yellow}else{Write-Error "No images in '$inpPath'."}}else{Write-Error "Path invalid: '$inpPath'"}

            if($srcPaths.Count -eq 0){$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true;return $cmdRes}
            $lastGeneratedDescription = $null # Variable to store the last description
            $idx=0;foreach($curPath in $srcPaths){
                $idx++;Write-Host "`nProcessing image $idx/$($srcPaths.Count): '$curPath'"-F Cyan;$descPrompt="Describe image vividly for AI generation.";Write-Host "Asking Gemini..."-F DarkGray;$dParams=@{ApiKey=$ApiKey;Model=$sessionConfig.Model;Prompt=$descPrompt;InlineFilePaths=@($curPath);ConversationHistory=@();TimeoutSec=$sessionConfig.TimeoutSec};if($sessionConfig.GenConfig){$dParams.GenerationConfig=$sessionConfig.GenConfig};$dRes=Invoke-GeminiApi @dParams;if(-not $dRes.Success){Write-Error "Failed get desc for '$curPath'.";continue};
                $lastGeneratedDescription=$dRes.GeneratedText; # Store the description
                Write-Host "Gemini Desc:"-F Green;Write-Host $lastGeneratedDescription -F Green;Write-Host "`nGenerating from desc..."-F Yellow;
                $vParams=@{ProjectId=$sessionConfig.VertexProjectId;LocationId=$sessionConfig.VertexLocationId;Prompt=$lastGeneratedDescription;OutputFolder=$sessionConfig.VertexDefaultOutputFolder;ModelId=$sessionConfig.VertexImageModel};
                if($IsVerbose){$vParams.Verbose=$true};
                # Call the function and discard any return value
                Start-VertexImageGeneration @vParams | Out-Null;
                if($sessionConfig.FileDelaySec -gt 0 -and $idx -lt $srcPaths.Count){Start-Sleep -Sec $sessionConfig.FileDelaySec}
            }
            # After processing all images, use the last description as the next prompt
            if ($lastGeneratedDescription) {
                $cmdRes.PromptOverride = $lastGeneratedDescription
                $cmdRes.CommandExecuted = $true
                $cmdRes.SkipApiCall = $false # Allow the main loop to call Gemini API
            } else {
                # If no description was generated (e.g., all image descriptions failed)
                Write-Warning "Could not generate a description from the source(s)."
                $cmdRes.CommandExecuted = $true
                $cmdRes.SkipApiCall = $true # Skip API call if no description
            }
        }
         '^/help$' {
            # Display Help Text
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
            Write-Host "  /back         - Cancel current input/selection prompt." -ForegroundColor Cyan
            Write-Host "  /help         - Show this command list." -ForegroundColor Cyan
            $cmdRes.CommandExecuted = $true; $cmdRes.SkipApiCall = $true # Corrected variable name
        }
        default { # Handle unrecognized commands
            Write-Warning "Unrecognized command: '$trimmedInput'. Type '/help' for options or '/exit' to quit."
            $cmdRes.CommandExecuted = $false; $cmdRes.SkipApiCall = $true # Corrected variable name, treat as no-op, don't call API
        }
    } # End Switch

    return $cmdRes
}

Write-Verbose "ChatUtils.ps1 loaded."
