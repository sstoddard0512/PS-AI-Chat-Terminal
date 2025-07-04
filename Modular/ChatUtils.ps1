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
        Write-Host "  /generate_from <path> - Describe image(s) at <path>, then generate new image(s). Prompts if path is missing or uses session media." -ForegroundColor Cyan
        Write-Host "  /model [name] - Change the Gemini model. If no name, shows list." -ForegroundColor Cyan
        Write-Host "  /adventuregame [theme] - Start an interactive choose-your-own-adventure game." -ForegroundColor Cyan
        Write-Host "  /escaperoom [theme] - Start an interactive escape room game." -ForegroundColor Cyan
        Write-Host "  /imagemodel [name] - Change the Vertex AI image generation model. If no name, shows list." -ForegroundColor Cyan
        Write-Host "  /simulatechat [initial_prompt] - Start a role-playing simulation. Prompts for personas and turns." -ForegroundColor Cyan
        Write-Host "  /tellajoke    - Ask Gemini to tell a joke." -ForegroundColor Cyan
        Write-Host "  /rolldice [NdN] - Ask Gemini to narrate a dice roll (e.g., 2d6). Defaults to 1d6." -ForegroundColor Cyan
        Write-Host "  /cointoss     - Perform a coin toss." -ForegroundColor Cyan
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
        '^/clear$'{Write-Host "`nClearing history."-F Yellow;$ConversationHistoryRef.Value = [System.Collections.ArrayList]::new();$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true} # Note: Caller must clear last prompt/result if needed
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
                                        $recursivePromptCancelled = true
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
                    $mediaAddedSuccessfully = false # Mark overall media addition as failed
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

            $fullCommandText = "/$cmd $prompt" # Store the full command text
            Write-Host "$fullCommandText command detected"-F Magenta; # Use full command text
            
            # Add user command to history
            [void]$ConversationHistoryRef.Value.Add(@{ role = 'user'; parts = @(@{text = $fullCommandText}) })
            Write-Verbose "Added user command '$fullCommandText' to history."

            $vParams=@{ProjectId=$sessionConfig.VertexProjectId;LocationId=$sessionConfig.VertexLocationId;Prompt=$prompt;OutputFolder=$sessionConfig.VertexDefaultOutputFolder;ModelId=$sessionConfig.VertexImageModel};
            if($IsVerbose){$vParams.Verbose=$true};
            
            $generatedImagePaths = Start-VertexImageGeneration @vParams # Capture returned paths
            
            if ($generatedImagePaths -and $generatedImagePaths.Count -gt 0) {
                $imagePathsString = $generatedImagePaths -join ", "
                $modelResponseText = "Image(s) generated: $imagePathsString"
                [void]$ConversationHistoryRef.Value.Add(@{ role = 'model'; parts = @(@{text = $modelResponseText}) })
                Write-Verbose "Added image generation result to history: $modelResponseText"
            } else {
                $modelResponseText = "Image generation initiated for '$prompt'. Check output folder. (No specific paths returned or generation failed)."
                [void]$ConversationHistoryRef.Value.Add(@{ role = 'model'; parts = @(@{text = $modelResponseText}) })
                Write-Verbose "Added image generation placeholder to history."
            }
            
            $cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true
        }
        '^/generate_from(\s+(.+))?$' { # Path is optional
            if(-not(Ensure-VertexAiConfig -Ses $SessionConfigRef)){$cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true;return $cmdRes}; $sessionConfig=$SessionConfigRef.Value;
            
            $inpPath = $null # Initialize $inpPath
            $initialPathArgument = if ($Matches[2]) { $Matches[2].Trim('"').Trim("'") } else { $null }

            if ($initialPathArgument) {
                # An argument was provided. Validate it.
                if (Test-Path -LiteralPath $initialPathArgument -PathType Leaf -ErrorAction SilentlyContinue) {
                    $inpPath = $initialPathArgument
                    Write-Verbose "[/generate_from] Using valid file path provided with command: '$inpPath'"
                } elseif (Test-Path -LiteralPath $initialPathArgument -PathType Container -ErrorAction SilentlyContinue) {
                    $inpPath = $initialPathArgument
                    Write-Verbose "[/generate_from] Using valid folder path provided with command: '$inpPath'"
                } else {
                    # The provided path argument is invalid.
                    Write-Warning "The path '$initialPathArgument' provided with /generate_from is invalid. Please enter a valid path below or use the default."
                    # $inpPath remains $null, so it will fall into the prompting logic below.
                }
            }

            if (-not $inpPath) { # If no argument OR invalid argument, then prompt.
                $validSessionMediaDefault = $null
                if (-not [string]::IsNullOrWhiteSpace($sessionConfig.Media)) {
                    Write-Verbose "[/generate_from] Checking sessionConfig.Media for default: '$($sessionConfig.Media)'"
                    if (Test-Path -LiteralPath $sessionConfig.Media) {
                        $validSessionMediaDefault = $sessionConfig.Media
                    } else {
                        Write-Warning "Session media path '$($sessionConfig.Media)' is invalid and cannot be used as a default."
                    }
                }

                # Construct the prompt message
                $promptMessage = "Enter source path for /generate_from"
                if ($validSessionMediaDefault) {
                    $promptMessage += " (default: '$validSessionMediaDefault')"
                }
                $promptMessage += " (or /back to cancel)"

                # Loop for path input
                while ($true) {
                    $userInputPath = Read-Host $promptMessage
                    $trimmedUserInput = $userInputPath.Trim()
                    $lowerTrimmedUserInput = $trimmedUserInput.ToLowerInvariant()

                    if ($lowerTrimmedUserInput -eq '/back') {
                        Write-Host "(Input cancelled)" -F Gray
                        # $inpPath remains null, will be caught by the check below
                        break 
                    }

                    if ([string]::IsNullOrWhiteSpace($trimmedUserInput)) {
                        if ($validSessionMediaDefault) {
                            $inpPath = $validSessionMediaDefault
                            Write-Host "Using default path: '$inpPath'" -ForegroundColor Gray
                            break
                        } else {
                            Write-Warning "Path cannot be empty. Please try again."
                        }
                    } else {
                        # User typed a path, validate it here before accepting
                        $potentialPath = $trimmedUserInput.Trim('"').Trim("'")
                        if ((Test-Path -LiteralPath $potentialPath -PathType Leaf -ErrorAction SilentlyContinue) -or `
                            (Test-Path -LiteralPath $potentialPath -PathType Container -ErrorAction SilentlyContinue)) {
                            $inpPath = $potentialPath
                            break
                        } else {
                            Write-Warning "The path '$potentialPath' entered is not a valid file or folder. Please try again."
                        }
                    }
                }
            } # End of prompting block
            
            # Check if a path was successfully obtained (either from argument or prompt)
            if ([string]::IsNullOrWhiteSpace($inpPath)) { 
                Write-Warning "No valid path provided or selected for /generate_from. Command cancelled."
                $cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true;return $cmdRes 
            }
            # At this point, $inpPath is non-empty and has passed at least one Test-Path check.

            $fullCommandText = "/generate_from $inpPath"
            # Add user command to history
            [void]$ConversationHistoryRef.Value.Add(@{ role = 'user'; parts = @(@{text = $fullCommandText}) })
            Write-Verbose "Added user command '$fullCommandText' to history."

            $srcPaths=[System.Collections.ArrayList]::new()
            # Now, determine if $inpPath (which should be valid) is a file or folder
            if (Test-Path -LiteralPath $inpPath -PathType Leaf -ErrorAction SilentlyContinue) {
                [void]$srcPaths.Add($inpPath)
                Write-Host "`n--- Gen From File: '$inpPath' ---"-F Yellow
            } elseif (Test-Path -LiteralPath $inpPath -PathType Container -ErrorAction SilentlyContinue) {
                $imgExt=@('.jpg','.jpeg','.png','.webp','.gif','.heic','.heif','.bmp','.tif','.tiff')
                $found=Get-ChildItem -LiteralPath $inpPath -File -ErrorAction SilentlyContinue | Where-Object {$imgExt -contains $_.Extension.ToLowerInvariant()}
                if($found){
                    $found | ForEach-Object {[void]$srcPaths.Add($_.FullName)}
                    Write-Host "`n--- Gen From Folder: '$inpPath' ($($found.Count) images) ---"-F Yellow
                } else {
                    # Folder is valid but contains no suitable images. $srcPaths will be empty.
                    Write-Warning "No supported image files found in folder '$inpPath'."
                }
            } else {
                # This case should be rare if the above logic is sound.
                # It implies $inpPath was non-empty, passed an initial Test-Path, but now fails for both Leaf and Container.
                Write-Error "Path '$inpPath' is no longer valid or is of an unsupported type. Command cancelled."
                $cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true;return $cmdRes
            }

            if($srcPaths.Count -eq 0){
                Write-Warning "No source images to process from '$inpPath'. Command cancelled."
                $cmdRes.CommandExecuted=$true;$cmdRes.SkipApiCall=$true;return $cmdRes
            }
            $lastGeneratedDescription = $null # Variable to store the last description
            $allGeneratedImagePaths = [System.Collections.ArrayList]::new() # To collect all paths from this command

            $idx=0;foreach($curPath in $srcPaths){
                $idx++;Write-Host "`nProcessing image $idx/$($srcPaths.Count): '$curPath'"-F Cyan;$descPrompt="Describe image vividly for AI generation.";Write-Host "Asking Gemini..."-F DarkGray;$dParams=@{ApiKey=$ApiKey;Model=$sessionConfig.Model;Prompt=$descPrompt;InlineFilePaths=@($curPath);ConversationHistory=@();TimeoutSec=$sessionConfig.TimeoutSec};if($sessionConfig.GenConfig){$dParams.GenerationConfig=$sessionConfig.GenConfig};$dRes=Invoke-GeminiApi @dParams;if(-not $dRes.Success){Write-Error "Failed get desc for '$curPath'.";continue};
                $lastGeneratedDescription=$dRes.GeneratedText; # Store the description
                
                $descHistoryText = "Description for '$curPath':`n$lastGeneratedDescription"
                [void]$ConversationHistoryRef.Value.Add(@{ role = 'model'; parts = @(@{text = $descHistoryText}) })
                Write-Verbose "Added image description to history."

                Write-Host "Gemini Desc:"-F Green;Write-Host $lastGeneratedDescription -F Green;Write-Host "`nGenerating from desc..."-F Yellow;
                $vParams=@{ProjectId=$sessionConfig.VertexProjectId;LocationId=$sessionConfig.VertexLocationId;Prompt=$lastGeneratedDescription;OutputFolder=$sessionConfig.VertexDefaultOutputFolder;ModelId=$sessionConfig.VertexImageModel};
                if($IsVerbose){$vParams.Verbose=$true};
                
                $newlyGeneratedPaths = Start-VertexImageGeneration @vParams # Capture paths
                if ($newlyGeneratedPaths -and $newlyGeneratedPaths.Count -gt 0) {
                    $newlyGeneratedPaths | ForEach-Object { [void]$allGeneratedImagePaths.Add($_) }
                    $genImageHistoryText = "Image(s) generated from description of '$curPath': $($newlyGeneratedPaths -join ', ')"
                    [void]$ConversationHistoryRef.Value.Add(@{ role = 'model'; parts = @(@{text = $genImageHistoryText}) })
                    Write-Verbose "Added generated image paths to history."
                } else {
                    $genImageHistoryText = "Image generation initiated from description of '$curPath'. Check output folder. (No specific paths returned or generation failed)."
                    [void]$ConversationHistoryRef.Value.Add(@{ role = 'model'; parts = @(@{text = $genImageHistoryText}) })
                    Write-Verbose "Added image generation placeholder to history."
                }

                if($sessionConfig.FileDelaySec -gt 0 -and $idx -lt $srcPaths.Count){Start-Sleep -Sec $sessionConfig.FileDelaySec}
            }
            # After processing all images, use the last description as the next prompt
            if ($lastGeneratedDescription) {
                $cmdRes.PromptOverride = $lastGeneratedDescription
                # Even though we have a prompt override, we don't want to immediately call the API with it.
                # The user can choose to use this context in their next manual prompt or /retry.
                $cmdRes.CommandExecuted = $true
                $cmdRes.SkipApiCall = $true
            } else {
                # If no description was generated (e.g., all image descriptions failed)
                Write-Warning "Could not generate a description from the source(s) to use as a prompt."
                $cmdRes.CommandExecuted = $true
                $cmdRes.SkipApiCall = $true
            }
        }
        '^/simulatechat(\s+(.+))?$' { # Regex updated to capture optional prompt
            $cmdRes.CommandExecuted = $true; $cmdRes.SkipApiCall = $true

            Write-Host "`n--- Chat Simulation ---" -ForegroundColor Magenta
            
            $initialSimPrompt = $null
            $providedSimPrompt = if ($Matches[2]) { $Matches[2].Trim().Trim('"').Trim("'") } else { $null }

            if ($providedSimPrompt) {
                $initialSimPrompt = $providedSimPrompt
                Write-Verbose "[/simulatechat] Using prompt provided with command: '$initialSimPrompt'"
            } else {
                while ($true) {
                    $initialSimPrompt = Read-Host "Enter the initial message to start the simulation (or /back to cancel)"
                    if ($initialSimPrompt.Trim().ToLowerInvariant() -eq '/back') {
                        Write-Host "(Simulation cancelled)" -F Gray; return $cmdRes
                    }
                    if (-not [string]::IsNullOrWhiteSpace($initialSimPrompt)) { break }
                    Write-Warning "Initial message cannot be empty. Please try again."
                }
            }

            # Prompt for Persona Names
            $personaAName = "Alice" # Default
            $personaBName = "Bob"   # Default
            while ($true) {
                $inputNameA = Read-Host "Enter name for Persona A (default: '$personaAName', or /back)"
                if ($inputNameA.Trim().ToLowerInvariant() -eq '/back') { Write-Host "(Simulation cancelled)" -F Gray; return $cmdRes }
                if (-not [string]::IsNullOrWhiteSpace($inputNameA)) { $personaAName = $inputNameA.Trim(); break }
                elseif ([string]::IsNullOrWhiteSpace($inputNameA)) { break } # Accept default
            }
            while ($true) {
                $inputNameB = Read-Host "Enter name for Persona B (default: '$personaBName', or /back)"
                if ($inputNameB.Trim().ToLowerInvariant() -eq '/back') { Write-Host "(Simulation cancelled)" -F Gray; return $cmdRes }
                if (-not [string]::IsNullOrWhiteSpace($inputNameB)) { $personaBName = $inputNameB.Trim(); break }
                elseif ([string]::IsNullOrWhiteSpace($inputNameB)) { break } # Accept default
            }
            if ($personaAName -eq $personaBName) { # Ensure different names for clarity
                $personaBName = "$($personaBName)_2"
                Write-Warning "Persona names were identical. Renamed Persona B to '$personaBName' for clarity."
            }
            Write-Host "Persona A: '$personaAName', Persona B: '$personaBName'" -F Gray

            # Prompt for Number of Turns
            $numberOfTurns = 0
            while ($true) {
                $turnInput = Read-Host "Enter total number of messages Gemini will generate in simulation (1-20, default 20 if empty, or /back)"
                $trimmedTurnInput = $turnInput.Trim()
                if ($trimmedTurnInput.ToLowerInvariant() -eq '/back') {
                    Write-Host "(Simulation cancelled)" -F Gray; return $cmdRes
                }
                if ([string]::IsNullOrWhiteSpace($trimmedTurnInput)) { # User pressed Enter
                    $numberOfTurns = 20
                    Write-Host "Defaulting to 20 turns." -F Gray
                    break
                }
                if ($trimmedTurnInput -match '^\d+$' -and ([int]$trimmedTurnInput -gt 0 -and [int]$trimmedTurnInput -le 20)) {
                    $numberOfTurns = [int]$trimmedTurnInput; break
                }
                Write-Warning "Please enter a valid number between 1 and 20, or press Enter for 20."
            }

            Write-Host "Starting simulation for $numberOfTurns Gemini messages..." -F Yellow
            
            # Display initial user prompt and add to main history
            Write-Host "`nUser (Initiator):" -F White
            Write-Host $initialSimPrompt
            [void]$ConversationHistoryRef.Value.Add(@{ role = 'user'; parts = @(@{text = "[Simulation Initiator] $initialSimPrompt"}) })

            $simulationApiHistory = [System.Collections.ArrayList]::new() # History for Invoke-GeminiApi context
            $currentInputForPersona = $initialSimPrompt # This is what the current persona will respond to
            $activePersonaName = $personaAName
            $otherPersonaName = $personaBName

            for ($turnCount = 1; $turnCount -le $numberOfTurns; $turnCount++) {
                Write-Host "`n--- Simulation Message $turnCount/$numberOfTurns ($activePersonaName) ---" -F DarkCyan
                
                # Construct the prompt for Gemini to act as the active persona
                $promptForGemini = "You are acting as '$activePersonaName'. The previous message in the conversation was: '$currentInputForPersona'. Please provide a response in character as '$activePersonaName'."
                Write-Verbose "[/simulatechat] Prompt for Gemini (as $activePersonaName): $promptForGemini"

                $invokeParams = @{
                    ApiKey              = $ApiKey
                    Model               = $sessionConfig.Model
                    TimeoutSec          = $sessionConfig.TimeoutSec
                    MaxRetries          = $sessionConfig.MaxRetries
                    InitialRetryDelaySec = $sessionConfig.InitialRetryDelaySec
                    Prompt              = $promptForGemini
                    ConversationHistory = $simulationApiHistory # Pass the API call history
                }
                if ($sessionConfig.GenerationConfig) { $invokeParams.GenerationConfig = $sessionConfig.GenerationConfig }

                $apiSimResult = $null
                Write-Host "$activePersonaName (Thinking...)" -NoNewline -F DarkGray
                try {
                    $apiSimResult = Invoke-GeminiApi @invokeParams
                } catch {
                    Write-Warning "`rError during simulation API call: $($_.Exception.Message)"
                    [void]$ConversationHistoryRef.Value.Add(@{role = 'model'; parts = @(@{text = "[Simulation Error] $($_.Exception.Message)"})})
                    break # Stop simulation on error
                } finally {
                     # Robust line clearing
                     Write-Host "`r" + (' ' * ($Host.UI.RawUI.WindowSize.Width - 1)) + "`r" -NoNewline
                }

                if ($apiSimResult -and $apiSimResult.Success) {
                    $personaColor = if($activePersonaName -eq $personaAName){[ConsoleColor]::Cyan}else{[ConsoleColor]::Magenta}
                    Write-Host "`r$($activePersonaName):" -F $personaColor # Overwrite thinking message
                    Write-Host $apiSimResult.GeneratedText -F Green
                    
                    # Add Gemini's actual response (as the persona) to the main chat history
                    [void]$ConversationHistoryRef.Value.Add(@{ role = 'model'; parts = @(@{text = "[$activePersonaName] $($apiSimResult.GeneratedText)"}) })
                    
                    $simulationApiHistory = $apiSimResult.UpdatedConversationHistory # Update API call history
                    $currentInputForPersona = $apiSimResult.GeneratedText # This becomes input for the next persona

                    if ([string]::IsNullOrWhiteSpace($currentInputForPersona)) { Write-Warning "$activePersonaName returned an empty response. Ending simulation."; break }

                    # Swap personas for the next turn
                    $tempName = $activePersonaName; $activePersonaName = $otherPersonaName; $otherPersonaName = $tempName;
                } else {
                    Write-Host "" # Newline after failed thinking message
                    $errorDetail = if ($apiSimResult) { "Status: $($apiSimResult.StatusCode), Error: $($apiSimResult.ErrorRecord.Exception.Message), Body: $($apiSimResult.ResponseBody)" } else { "API result was null." }
                    Write-Warning "Simulation API call for $activePersonaName failed. $errorDetail"
                    [void]$ConversationHistoryRef.Value.Add(@{role = 'model'; parts = @(@{text = "[Simulation Error - $activePersonaName] API call failed. $errorDetail"})})
                    break # Stop simulation on error
                }
                 if ($turnCount -lt $numberOfTurns) { Start-Sleep -Seconds 1 } # Small delay between turns to be kind to API
            }
            Write-Host "`n--- Simulation Ended ---" -ForegroundColor Magenta
            return $cmdRes
        }
        '^/tellajoke$' {
            $cmdRes.PromptOverride = "Tell me a joke."
            $cmdRes.CommandExecuted = $true
            $cmdRes.SkipApiCall = $false # Let the main loop handle the API call
            Write-Host "Asking Gemini for a joke..." -F DarkGray
        }
        '^/rolldice(\s+(\S+))?$' {
            $diceNotation = if ($Matches[2]) { $Matches[2].Trim() } else { "1d6" }
            # Basic validation for dice notation (can be expanded)
            if ($diceNotation -notmatch '^\d+[dD]\d+$' -and $diceNotation -notmatch '^[dD]\d+$') {
                if ($diceNotation -notmatch '^\d+$') { # allow just a number for dX
                     Write-Warning "Invalid dice notation '$diceNotation'. Using '1d6'. Expected format like '2d6', 'd20', or '6'."
                     $diceNotation = "1d6"
                } else { # if it's just a number, assume d<number>
                    $diceNotation = "d$diceNotation"
                }
            }
            $cmdRes.PromptOverride = "Narrate the result of rolling $diceNotation dice."
            $cmdRes.CommandExecuted = $true
            $cmdRes.SkipApiCall = $false # Let the main loop handle the API call
            Write-Host "Asking Gemini to roll $diceNotation..." -F DarkGray
        }
        '^/cointoss$' {
            $cmdRes.CommandExecuted = $true; $cmdRes.SkipApiCall = $true # Local command
            $result = if ((Get-Random -Minimum 0 -Maximum 2) -eq 0) { "Heads" } else { "Tails" }
            $outputText = "Coin toss result: $result"
            Write-Host "`n$outputText" -F Green
            # Add to main conversation history
            [void]$ConversationHistoryRef.Value.Add(@{ role = 'user'; parts = @(@{text = "/cointoss"}) })
            [void]$ConversationHistoryRef.Value.Add(@{ role = 'model'; parts = @(@{text = $outputText}) })
        }
        '^/escaperoom(\s+(.+))?$' {
            $cmdRes.CommandExecuted = $true; $cmdRes.SkipApiCall = $true
            Write-Host "`n--- Starting Escape Room Game ---" -ForegroundColor Magenta

            $escapeRoomTheme = "a mysterious locked library" # Default theme
            if ($Matches[2]) {
                $escapeRoomTheme = $Matches[2].Trim()
            } else {
                Write-Host "No theme specified for the escape room. Asking Gemini for some ideas..." -F DarkGray
                $themeSuggestionPrompt = "Suggest 3-5 diverse and interesting themes for a text-based escape room game. Present them as a numbered list. For example: '1. A high-tech laboratory with a rogue AI.' or '2. An ancient pharaoh's tomb filled with traps.'"
                $themeInvokeParams = @{
                    ApiKey              = $ApiKey; Model = $sessionConfig.Model; TimeoutSec = $sessionConfig.TimeoutSec
                    MaxRetries          = $sessionConfig.MaxRetries; InitialRetryDelaySec = $sessionConfig.InitialRetryDelaySec
                    Prompt              = $themeSuggestionPrompt; ConversationHistory = @()
                }
                if ($sessionConfig.GenerationConfig) { $themeInvokeParams.GenerationConfig = $sessionConfig.GenerationConfig }

                $apiThemeResult = $null
                try { $apiThemeResult = Invoke-GeminiApi @themeInvokeParams } catch { Write-Warning "Error getting escape room theme suggestions: $($_.Exception.Message)" }

                $suggestedThemes = [System.Collections.ArrayList]::new()
                if ($apiThemeResult -and $apiThemeResult.Success -and -not [string]::IsNullOrWhiteSpace($apiThemeResult.GeneratedText)) {
                    Write-Host "Gemini suggests these escape room themes:" -F Green; Write-Host $apiThemeResult.GeneratedText -F Green
                    $apiThemeResult.GeneratedText -split '\r?\n' | ForEach-Object { if ($_ -match '^\s*\d+\.\s*(.+)') { [void]$suggestedThemes.Add($Matches[1].Trim()) } }
                } else { Write-Warning "Could not get theme suggestions. You can enter your own or use the default." }

                $promptMessage = "Enter a theme (e.g., 'abandoned spaceship'), choose a number from suggestions, press Enter for default '$escapeRoomTheme', or /back to cancel"
                $customThemeInput = Read-Host $promptMessage

                if ($customThemeInput.Trim().ToLowerInvariant() -eq '/back') { Write-Host "(Escape room game cancelled)" -F Gray; return $cmdRes }

                if ($customThemeInput -match '^\d+$' -and [int]$customThemeInput -ge 1 -and [int]$customThemeInput -le $suggestedThemes.Count) {
                    $escapeRoomTheme = $suggestedThemes[[int]$customThemeInput - 1]
                    Write-Host "Selected theme: '$escapeRoomTheme'" -F Yellow
                } elseif (-not [string]::IsNullOrWhiteSpace($customThemeInput)) { $escapeRoomTheme = $customThemeInput.Trim() }
            }
            Write-Host "Escape Room Theme: '$escapeRoomTheme'. Type '/exit' during your turn to end the game." -F Yellow

            $systemPrompt = @"
You are an Escape Room Game Master.
The player has chosen the theme: '$escapeRoomTheme'.

Your role is to guide the player through an interactive escape room scenario. The player needs to solve puzzles, find clues, and use items to escape the room. The game must be winnable.

**Your Turn Structure:**
1.  **Describe the Room/Area:** Vividly describe the current part of the room, any notable objects, puzzles, or interactive elements. If the player has items, remind them implicitly or if relevant to the current puzzle.
2.  **Present Choices:** Offer 2 to 4 clearly numbered choices for actions the player can take (e.g., "1. Examine the dusty bookshelf.", "2. Try the silver key on the locked drawer.", "3. Look under the rug."). Choices should be logical actions within an escape room.
3.  **Acknowledge Previous Choice (Optional but good):** Briefly acknowledge the player's last action and its immediate result if it makes sense narratively.

**Game Endings:**
*   **WIN (ESCAPED):** If the player successfully solves all necessary puzzles and finds the way out, clearly state "CONGRATULATIONS, YOU ESCAPED!" and provide a brief, satisfying concluding narrative of their escape.
*   **GAME OVER (FAILED):** If the player makes a critical mistake that makes escape impossible, or if an implicit timer (managed by you narratively) runs out, clearly state "GAME OVER. You failed to escape." and briefly explain why.

**Important Rules:**
*   **Winnable Path:** Always ensure there is a logical sequence of actions and puzzle solutions that leads to escape.
*   **Puzzles & Clues:** Puzzles should be solvable with information and items found within the room. Clues should be discoverable.
*   **Implicit Inventory:** You, the Game Master, will keep track of items the player has found or important states of objects. The player doesn't need to manage an explicit inventory list unless you decide to present it as part of the narrative.
*   **Stay In Character:** Do not break character.
*   **Clarity:** Make choices and their potential immediate implications clear.
*   **Progression:** The game must progress. Avoid dead ends unless they are red herrings that can be identified.
*   **No External Knowledge:** Base the game only on the theme and player choices. Do not ask for external input beyond their choice number.
*   **Response Format:** Respond ONLY with the game narrative and the numbered choices. Do not include conversational pleasantries like "What would you like to do?".

Let's begin the escape room! Based on the theme '$escapeRoomTheme', present the initial view of the room and the first set of choices.
"@
            [void]$ConversationHistoryRef.Value.Add(@{ role = 'user'; parts = @(@{text = "/escaperoom theme: $escapeRoomTheme"}) })

            $escapeRoomApiHistory = [System.Collections.ArrayList]::new()
            $currentEscapeRoomPrompt = $systemPrompt
            $gameEnded = $false

            while (-not $gameEnded) {
                $invokeParams = @{
                    ApiKey = $ApiKey; Model = $sessionConfig.Model; TimeoutSec = $sessionConfig.TimeoutSec
                    MaxRetries = $sessionConfig.MaxRetries; InitialRetryDelaySec = $sessionConfig.InitialRetryDelaySec
                    Prompt = $currentEscapeRoomPrompt; ConversationHistory = $escapeRoomApiHistory
                }
                if ($sessionConfig.GenerationConfig) { $invokeParams.GenerationConfig = $sessionConfig.GenerationConfig }

                Write-Host "`nGame Master (Thinking...)" -NoNewline -F DarkGray; $apiGameResult = $null
                try { $apiGameResult = Invoke-GeminiApi @invokeParams }
                catch { Write-Warning "`rError during escape room API call: $($_.Exception.Message)";[void]$ConversationHistoryRef.Value.Add(@{role = 'model'; parts = @(@{text = "[Escape Room Error] $($_.Exception.Message)"})});$gameEnded = $true;continue }
                finally { Write-Host "`r" + (' ' * ($Host.UI.RawUI.WindowSize.Width - 1)) + "`r" -NoNewline }

                if ($apiGameResult -and $apiGameResult.Success) {
                    $gameMasterResponse = $apiGameResult.GeneratedText
                    Write-Host "`rGame Master:" -F Green; Write-Host $gameMasterResponse -F Green
                    [void]$ConversationHistoryRef.Value.Add(@{ role = 'model'; parts = @(@{text = "[Escape Room] $gameMasterResponse"}) })
                    $escapeRoomApiHistory = $apiGameResult.UpdatedConversationHistory

                    if ($gameMasterResponse -match "GAME OVER." -or $gameMasterResponse -match "CONGRATULATIONS, YOU ESCAPED!") { Write-Host "--- Escape Room Game Ended ---" -F Magenta;$gameEnded = $true;continue }

                    $playerChoiceInput = $null
                    while ($true) {
                        $playerChoiceInput = Read-Host "`nYour Action (enter number, or /exit to end game, or /back to re-enter choice)"
                        if ($playerChoiceInput.Trim().ToLowerInvariant() -eq '/exit') { Write-Host "Exiting escape room." -F Yellow;[void]$ConversationHistoryRef.Value.Add(@{ role = 'user'; parts = @(@{text = "[Escape Room] /exit"}) });$gameEnded = $true;break }
                        if ($playerChoiceInput.Trim().ToLowerInvariant() -eq '/back') { Write-Host "(Re-enter action)" -F Gray; continue }
                        if ($playerChoiceInput -match '^\d+$' -or -not [string]::IsNullOrWhiteSpace($playerChoiceInput)) { break }
                        Write-Warning "Please enter an action number, /exit, or /back."
                    }
                    if ($gameEnded) { continue }
                    $currentEscapeRoomPrompt = "My action is: $($playerChoiceInput.Trim())"
                    [void]$ConversationHistoryRef.Value.Add(@{ role = 'user'; parts = @(@{text = "[Escape Room] Action: $($playerChoiceInput.Trim())"}) })
                } else {
                    $errorDetail = if ($apiGameResult) { "Status: $($apiGameResult.StatusCode), Error: $($apiGameResult.ErrorRecord.Exception.Message), Body: $($apiGameResult.ResponseBody)" } else { "API result was null." }
                    Write-Warning "`rEscape room API call failed. $errorDetail"
                    [void]$ConversationHistoryRef.Value.Add(@{role = 'model'; parts = @(@{text = "[Escape Room Error] API call failed. $errorDetail"})})
                    $gameEnded = $true
                }
            } # End while game not ended
            return $cmdRes
        }
        '^/adventuregame(\s+(.+))?$' {
            $cmdRes.CommandExecuted = $true; $cmdRes.SkipApiCall = $true
            Write-Host "`n--- Starting Adventure Game ---" -ForegroundColor Magenta

            $adventureTheme = "a classic fantasy setting with dragons and treasure" # Default theme
            if ($Matches[2]) {
                $adventureTheme = $Matches[2].Trim()
            } else {
                Write-Host "No theme specified. Asking Gemini for some ideas..." -F DarkGray
                $themeSuggestionPrompt = "Suggest 3-5 diverse and interesting themes for a text-based choose-your-own-adventure game. Present them as a numbered list. For example: '1. A thrilling spy mission in modern-day Paris.' or '2. Surviving a zombie apocalypse in a deserted shopping mall.'"
                $themeInvokeParams = @{
                    ApiKey              = $ApiKey
                    Model               = $sessionConfig.Model # Use the current session model
                    TimeoutSec          = $sessionConfig.TimeoutSec
                    MaxRetries          = $sessionConfig.MaxRetries
                    InitialRetryDelaySec = $sessionConfig.InitialRetryDelaySec
                    Prompt              = $themeSuggestionPrompt
                    ConversationHistory = @() # Fresh history for this one-off request
                }
                if ($sessionConfig.GenerationConfig) { $themeInvokeParams.GenerationConfig = $sessionConfig.GenerationConfig }

                $apiThemeResult = $null
                try { $apiThemeResult = Invoke-GeminiApi @themeInvokeParams } catch { Write-Warning "Error getting theme suggestions: $($_.Exception.Message)" }

                $suggestedThemes = [System.Collections.ArrayList]::new()
                if ($apiThemeResult -and $apiThemeResult.Success -and -not [string]::IsNullOrWhiteSpace($apiThemeResult.GeneratedText)) {
                    Write-Host "Gemini suggests these themes:" -F Green
                    Write-Host $apiThemeResult.GeneratedText -F Green
                    # Basic parsing of numbered list (assumes "N. Theme text")
                    $apiThemeResult.GeneratedText -split '\r?\n' | ForEach-Object {
                        if ($_ -match '^\s*\d+\.\s*(.+)') { [void]$suggestedThemes.Add($Matches[1].Trim()) }
                    }
                } else {
                    Write-Warning "Could not get theme suggestions from Gemini. You can enter your own or use the default."
                }

                $promptMessage = "Enter a theme (e.g., 'space exploration'), choose a number from suggestions, press Enter for default '$adventureTheme', or /back to cancel"
                $customThemeInput = Read-Host $promptMessage

                if ($customThemeInput.Trim().ToLowerInvariant() -eq '/back') { Write-Host "(Adventure game cancelled)" -F Gray; return $cmdRes }

                if ($customThemeInput -match '^\d+$' -and [int]$customThemeInput -ge 1 -and [int]$customThemeInput -le $suggestedThemes.Count) {
                    $adventureTheme = $suggestedThemes[[int]$customThemeInput - 1]
                    Write-Host "Selected theme: '$adventureTheme'" -F Yellow
                } elseif (-not [string]::IsNullOrWhiteSpace($customThemeInput)) {
                    $adventureTheme = $customThemeInput.Trim()
                }
                # If input was empty, $adventureTheme remains the default
            }
            Write-Host "Theme: '$adventureTheme'. Type '/exit' during your turn to end the game." -F Yellow

            $systemPrompt = @"
You are a Text Adventure Game Master.
The player has chosen the theme: '$adventureTheme'.

Your role is to guide the player through an interactive story that is engaging, coherent, and ultimately winnable.

**Your Turn Structure:**
1.  **Describe the Scene:** Vividly describe the current situation, environment, any characters, and relevant objects or events.
2.  **Present Choices:** Offer 2 to 4 clearly numbered choices (e.g., "1. Open the door.", "2. Examine the chest."). Each choice should lead to a distinct and meaningful consequence.
3.  **Acknowledge Previous Choice (Optional but good):** Briefly acknowledge the player's last choice if it makes sense narratively.

**Game Endings:**
*   **WIN:** If the player makes choices that lead to successfully completing the adventure's main objective, clearly state "CONGRATULATIONS, YOU WIN!" and provide a satisfying concluding narrative.
*   **GAME OVER:** If the player makes choices that lead to a definitive failure (e.g., character death, irreversible bad outcome), clearly state "GAME OVER." and briefly explain the reason.

**Important Rules:**
*   **Winnable Path:** Always ensure there is a logical sequence of choices that leads to a win.
*   **Stay In Character:** Do not break character or provide meta-commentary unless it's part of the game's narrative (e.g., a mysterious narrator).
*   **Clarity:** Make the choices and their potential immediate implications clear.
*   **Progression:** The story must progress with each choice. Avoid loops unless they are a specific puzzle.
*   **No External Knowledge:** Base the story only on the theme provided and the player's choices within the game. Do not ask the player for external input beyond their choice number.
*   **Response Format:** Respond ONLY with the game narrative and the numbered choices. Do not include conversational pleasantries like "What would you like to do?".

Let's begin the adventure! Based on the theme '$adventureTheme', present the very first scene and choices.
"@
            [void]$ConversationHistoryRef.Value.Add(@{ role = 'user'; parts = @(@{text = "/adventuregame theme: $adventureTheme"}) })

            $adventureGameApiHistory = [System.Collections.ArrayList]::new() # History for Invoke-GeminiApi context
            $currentAdventurePrompt = $systemPrompt
            $gameEnded = $false

            while (-not $gameEnded) {
                $invokeParams = @{
                    ApiKey              = $ApiKey
                    Model               = $sessionConfig.Model
                    TimeoutSec          = $sessionConfig.TimeoutSec
                    MaxRetries          = $sessionConfig.MaxRetries
                    InitialRetryDelaySec = $sessionConfig.InitialRetryDelaySec
                    Prompt              = $currentAdventurePrompt
                    ConversationHistory = $adventureGameApiHistory
                }
                if ($sessionConfig.GenerationConfig) { $invokeParams.GenerationConfig = $sessionConfig.GenerationConfig }

                Write-Host "`nGame Master (Thinking...)" -NoNewline -F DarkGray
                $apiGameResult = $null
                try { $apiGameResult = Invoke-GeminiApi @invokeParams }
                catch { Write-Warning "`rError during adventure game API call: $($_.Exception.Message)";[void]$ConversationHistoryRef.Value.Add(@{role = 'model'; parts = @(@{text = "[Adventure Game Error] $($_.Exception.Message)"})});$gameEnded = $true;continue }
                finally { Write-Host "`r" + (' ' * ($Host.UI.RawUI.WindowSize.Width - 1)) + "`r" -NoNewline }

                if ($apiGameResult -and $apiGameResult.Success) {
                    $gameMasterResponse = $apiGameResult.GeneratedText
                    Write-Host "`rGame Master:" -F Green; Write-Host $gameMasterResponse -F Green
                    [void]$ConversationHistoryRef.Value.Add(@{ role = 'model'; parts = @(@{text = "[Adventure Game] $gameMasterResponse"}) })
                    $adventureGameApiHistory = $apiGameResult.UpdatedConversationHistory

                    if ($gameMasterResponse -match "GAME OVER." -or $gameMasterResponse -match "CONGRATULATIONS, YOU WIN!") { Write-Host "--- Adventure Game Ended ---" -F Magenta;$gameEnded = $true;continue }

                    $playerChoiceInput = $null
                    while ($true) {
                        $playerChoiceInput = Read-Host "`nYour Choice (enter number, or /exit to end game, or /back to re-enter choice)"
                        if ($playerChoiceInput.Trim().ToLowerInvariant() -eq '/exit') { Write-Host "Exiting adventure game." -F Yellow;[void]$ConversationHistoryRef.Value.Add(@{ role = 'user'; parts = @(@{text = "[Adventure Game] /exit"}) });$gameEnded = $true;break }
                        if ($playerChoiceInput.Trim().ToLowerInvariant() -eq '/back') { Write-Host "(Re-enter choice)" -F Gray; continue }
                        if ($playerChoiceInput -match '^\d+$' -or -not [string]::IsNullOrWhiteSpace($playerChoiceInput)) { break } # Allow free text or numbers
                        Write-Warning "Please enter a choice number, /exit, or /back."
                    }
                    if ($gameEnded) { continue }
                    $currentAdventurePrompt = "My choice is: $($playerChoiceInput.Trim())"
                    [void]$ConversationHistoryRef.Value.Add(@{ role = 'user'; parts = @(@{text = "[Adventure Game] Choice: $($playerChoiceInput.Trim())"}) })
                } else {
                    $errorDetail = if ($apiGameResult) { "Status: $($apiGameResult.StatusCode), Error: $($apiGameResult.ErrorRecord.Exception.Message), Body: $($apiGameResult.ResponseBody)" } else { "API result was null." }
                    Write-Warning "`rAdventure game API call failed. $errorDetail"
                    [void]$ConversationHistoryRef.Value.Add(@{role = 'model'; parts = @(@{text = "[Adventure Game Error] API call failed. $errorDetail"})})
                    $gameEnded = $true
                }
            } # End while game not ended
            return $cmdRes
        }
        '^/cointoss$' {
            $cmdRes.CommandExecuted = $true; $cmdRes.SkipApiCall = $true # Local command
            $result = if ((Get-Random -Minimum 0 -Maximum 2) -eq 0) { "Heads" } else { "Tails" }
            $outputText = "Coin toss result: $result"
            Write-Host "`n$outputText" -F Green
            # Add to main conversation history
            [void]$ConversationHistoryRef.Value.Add(@{ role = 'user'; parts = @(@{text = "/cointoss"}) })
            [void]$ConversationHistoryRef.Value.Add(@{ role = 'model'; parts = @(@{text = $outputText}) })
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
            Write-Host "  /generate_from <path> - Describe image(s) at <path>, then generate new image(s). Prompts if path is missing or uses session media." -ForegroundColor Cyan
            Write-Host "  /model [name] - Change the Gemini model. If no name, shows list." -ForegroundColor Cyan
            Write-Host "  /adventuregame [theme] - Start an interactive choose-your-own-adventure game." -ForegroundColor Cyan
            Write-Host "  /escaperoom [theme] - Start an interactive escape room game." -ForegroundColor Cyan
            Write-Host "  /imagemodel [name] - Change the Vertex AI image generation model. If no name, shows list." -ForegroundColor Cyan
            Write-Host "  /simulatechat [initial_prompt] - Start a role-playing simulation. Prompts for personas and turns." -ForegroundColor Cyan
            Write-Host "  /tellajoke    - Ask Gemini to tell a joke." -ForegroundColor Cyan
            Write-Host "  /rolldice [NdN] - Ask Gemini to narrate a dice roll (e.g., 2d6). Defaults to 1d6." -ForegroundColor Cyan
            Write-Host "  /cointoss     - Perform a coin toss." -ForegroundColor Cyan
            Write-Host "  /exit         - Exit the chat session." -ForegroundColor Cyan
            Write-Host "  /back         - Cancel current input/selection prompt." -ForegroundColor Cyan
            Write-Host "  /help         - Show this command list." -ForegroundColor Cyan
            $cmdRes.CommandExecuted = $true; $cmdRes.SkipApiCall = $true 
        }
        default { 
            Write-Warning "Unrecognized command: '$trimmedInput'. Type '/help' for options or '/exit' to quit."
            $cmdRes.CommandExecuted = $false; $cmdRes.SkipApiCall = $true 
        }
    } # End Switch

    return $cmdRes
}

Write-Verbose "ChatUtils.ps1 loaded."
