# Start-GeminiChat.ps1
# Main script file containing the Start-GeminiChat function.
# Orchestrates the chat session by calling helper functions from other files.

#Requires -Version 7
<#
.SYNOPSIS
Starts a modular, interactive chat session with Google Gemini, supporting initial media file processing, metadata modifications, location processing, interactive media uploads, and Vertex AI image generation.
.DESCRIPTION
(Full description identical to modular v4.0.0 header)
.NOTES
Version: 4.0.0 (Refactored from v3.5.11)
Depends on: CoreUtils.ps1, GeminiApiUtils.ps1, VertexApiUtils.ps1, FileProcessingUtils.ps1, ChatUtils.ps1
#>

# --- Dot-Source Helper Scripts ---
try {
    Write-Verbose "Loading helper modules..."
    . (Join-Path -Path $PSScriptRoot -ChildPath "CoreUtils.ps1")
    . (Join-Path -Path $PSScriptRoot -ChildPath "GeminiApiUtils.ps1")
    . (Join-Path -Path $PSScriptRoot -ChildPath "VertexApiUtils.ps1")
    . (Join-Path -Path $PSScriptRoot -ChildPath "FileProcessingUtils.ps1")
    . (Join-Path -Path $PSScriptRoot -ChildPath "ChatUtils.ps1")
    Write-Verbose "Helper modules loaded."
} catch { Write-Error "Failed to load required helper scripts. Error: $($_.Exception.Message)"; return }

# --- Main Chat Function ---
function Start-GeminiChat {
    [CmdletBinding()]
    param(
        [Parameter(HelpMessage = "Your Google Gemini API Key. If omitted, you will be prompted.")] [string]$ApiKey,
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
        [Parameter(HelpMessage = "Author name for -UpdateAuthor.")] [string]$AuthorName,
        [Parameter(HelpMessage = "Update 'Comment' metadata from Title (requires -ModifyFiles).")] [switch]$UpdateSubject,
        [Parameter(HelpMessage = "Parse 'Tags:'/'Keywords:' and overwrite metadata (requires -ModifyFiles & ExifTool).")] [switch]$UpdateTags,
        [Parameter(HelpMessage = "Parse 'Rating:' and update metadata/append to filename (requires -ModifyFiles).")] [switch]$UpdateRating,
        [Parameter(HelpMessage = "Enables location processing (GPS read, AI prompt, Filename/Meta update). Requires -ModifyFiles & ExifTool.")] [switch]$UpdateLocation,
        [Parameter(HelpMessage = "Parse 'Description:' and update metadata (requires -ModifyFiles).")] [switch]$UpdateDescription,
        [Parameter(HelpMessage="Optional. Full path to exiftool.exe if not in system PATH.")] [string]$ExifToolPath,
        [Parameter(HelpMessage = "Optional file to append Gemini prompts and responses from initial media processing.")] [string]$OutputFile,
        [Parameter(HelpMessage = "Optional file to append the interactive chat log and errors.")] [string]$LogFile,
        [Parameter(HelpMessage="Google Cloud Project ID for Vertex AI Image Generation.")] [string]$VertexProjectId,
        [Parameter(HelpMessage="Google Cloud Location ID (e.g., 'us-central1') for Vertex AI.")] [string]$VertexLocationId,
        [Parameter(HelpMessage="Default output folder for Vertex AI generated images.")] [string]$VertexDefaultOutputFolder,
        [Parameter(HelpMessage="The Vertex AI Imagen model ID (e.g., 'imagegeneration@006').")] [string]$VertexImageModel = 'imagegeneration@006',
        [Parameter(HelpMessage="Optional file path to export the full conversation history as a CSV file upon exiting.")] [string]$CsvOutputFile,
        [Parameter(HelpMessage="Optional file path to save the parsed Gemini results for each processed file as a CSV.")] [string]$ResultsCsvFile,
        [Parameter(HelpMessage="Optional media path (file or folder) to be used as the initial context or for the first turn if -StartPrompt is also used. Can also be used by the /media command if no path is provided to it.")] [string]$Media,
        [Parameter(HelpMessage="[Switch] Attempt to compress video files using FFmpeg before uploading.")] [switch]$CompressMedia,
        [Parameter(HelpMessage="Optional. Full path to ffmpeg.exe if not in system PATH. Required if -CompressMedia is used.")] [string]$FFmpegPath,
        [Parameter(HelpMessage="FFmpeg compression preset ('fast', 'medium', 'slow').")] [ValidateSet('fast', 'medium', 'slow')] [string]$CompressionPreset = 'medium'
    )

    $originalVerbosePreference = $VerbosePreference
    $isVerboseSwitchPresent = $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')
    if ($isVerboseSwitchPresent) { $VerbosePreference = 'Continue'; Write-Host "[Start-GeminiChat] Verbose logging enabled." -ForegroundColor DarkGray }

    # --- API Key Input ---
    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        Write-Host "API Key required." -F Yellow
        while ($true) {
            $secKey = $null
            $currentApiKeyAttempt = $null
            try {
                $secKey = Read-Host "Enter Google Gemini API Key (or press Enter to cancel)" -AsSecureString

                if ($secKey.Length -gt 0) {
                    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secKey)
                    $currentApiKeyAttempt = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

                    if (-not [string]::IsNullOrWhiteSpace($currentApiKeyAttempt)) {
                        $ApiKey = $currentApiKeyAttempt # Assign to the function's $ApiKey
                        # $PSCmdlet.MyInvocation.BoundParameters['ApiKey'] will be updated after the loop if successful
                        break # Valid API key provided, exit loop
                    } else {
                        Write-Warning "API Key was provided but resulted in an empty string after processing. Please try again."
                        # Loop continues
                    }
                } else {
                    # User pressed Enter without typing anything
                    $confirmChoice = ''
                    while ($true) {
                        $choiceInput = Read-Host "API Key was not provided. Exit script? (y/n)"
                        $confirmChoice = $choiceInput.Trim().ToLowerInvariant()
                        if ($confirmChoice -in ('y', 'n')) { break }
                        Write-Warning "Invalid input. Please enter 'y' or 'n'."
                    }

                    if ($confirmChoice -eq 'y') {
                        Write-Host "Exiting: No API Key provided." -ForegroundColor Yellow
                        return # Exits the Start-GeminiChat function
                    }
                    # If 'n', the loop continues, and user will be prompted for API key again.
                    Write-Host "Please try entering the API Key again." -ForegroundColor Yellow
                }
            }
            catch {
                Write-Error "An error occurred while processing the API Key: $($_.Exception.Message)"
                $errorChoiceInput = Read-Host "An error occurred. Try again or exit? (try/exit)"
                if ($errorChoiceInput.Trim().ToLowerInvariant() -eq 'exit') {
                    return # Exits the Start-GeminiChat function
                }
            }
            finally {
                if ($secKey -ne $null) {
                    $secKey.Dispose()
                }
            }
        }
        $PSCmdlet.MyInvocation.BoundParameters['ApiKey'] = $ApiKey
    }

    $sessionConfig = Initialize-GeminiChatSession -BoundParameters $PSCmdlet.MyInvocation.BoundParameters -Invocation $PSCmdlet.MyInvocation -IsVerbose $isVerboseSwitchPresent
    if (-not $sessionConfig) { Write-Error "Session initialization failed."; return }

    # CRITICAL: Ensure $conversationHistory is an ArrayList
    $conversationHistory = [System.Collections.ArrayList]::new()
    $lastUserPrompt = $null
    $lastApiResult = $null
    $globalRenameErrors = [System.Collections.ArrayList]::new()
    $globalMetadataErrors = [System.Collections.ArrayList]::new()
    $isFirstTurn = $true

    try {
        while ($true) {
            $currentPromptInput = $null; $apiResult = $null
            $currentImageFolder = $null; $currentVideoFolder = $null; $currentRecurse = $false; $currentInlineFilePaths = $null
            $mediaAddedThisTurn = $false

            if ($isFirstTurn) {
                $isFirstTurn = $false
                if ($sessionConfig.MediaFolder) {
                    if (Process-InitialMediaFiles -SessionConfig $sessionConfig -ApiKey $ApiKey -StartPrompt $StartPrompt -GlobalRenameErrors $globalRenameErrors -GlobalMetadataErrors $globalMetadataErrors) { continue }
                    else { Write-Warning "Initial file processing issue. Proceeding interactively." }
                } elseif ($StartPrompt) { $currentPromptInput = $StartPrompt; Write-Host "`nYou (Start): $currentPromptInput" -F White }
                else { $currentPromptInput = Get-ChatInput -SessionConfig $sessionConfig -IsFirstInteractiveTurn $true; if ($currentPromptInput -eq '/exit') { break } }
            } else { $currentPromptInput = Get-ChatInput -SessionConfig $sessionConfig -IsFirstInteractiveTurn $false; if ($currentPromptInput -eq '/exit') { break } }

            # Ensure $conversationHistory is an ArrayList before passing by reference
            if ($conversationHistory -isnot [System.Collections.ArrayList]) {
                Write-Warning "[Start-GeminiChat] CRITICAL: conversationHistory was $($conversationHistory.GetType().FullName), expected ArrayList. Re-initializing."
                $tempList = [System.Collections.ArrayList]::new()
                if ($null -ne $conversationHistory) { foreach($item in $conversationHistory) { [void]$tempList.Add($item) } }
                $conversationHistory = $tempList
            }

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
                -CurrentInlineFilePathsRef ([ref]$currentInlineFilePaths) `
                -IsVerbose $isVerboseSwitchPresent

            if ($null -eq $commandResult) { Write-Error "Handle-ChatCommand returned null. Skipping."; continue }

            $currentPromptInput = if ($commandResult.PromptOverride -ne $null) { $commandResult.PromptOverride } else { $currentPromptInput }
            $mediaAddedThisTurn = $commandResult.MediaAdded
            if ($currentPromptInput.Trim() -eq '/clear') { $lastUserPrompt = $null; $lastApiResult = $null }
            if ($commandResult.ExitSession) { break }
            if ($commandResult.SkipApiCall) { Write-Host "---" -F Cyan; continue }

            if ($currentPromptInput -ne $null) {
                $lastUserPrompt = $currentPromptInput
                $invokeParams = @{ ApiKey = $ApiKey; Model = $sessionConfig.Model; TimeoutSec = $sessionConfig.TimeoutSec; MaxRetries = $sessionConfig.MaxRetries; InitialRetryDelaySec = $sessionConfig.InitialRetryDelaySec; Prompt = $currentPromptInput; ConversationHistory = $conversationHistory; CompressMedia = $sessionConfig.CompressMedia; FFmpegPath = $sessionConfig.FFmpegPath; CompressionPreset = $sessionConfig.CompressionPreset }
                if ($sessionConfig.GenerationConfig) { $invokeParams.GenerationConfig = $sessionConfig.GenerationConfig }
                if ($mediaAddedThisTurn) {
                    if ($currentImageFolder) { $invokeParams.ImageFolder=$currentImageFolder }
                    if ($currentVideoFolder) { $invokeParams.VideoFolder=$currentVideoFolder }
                    if ($currentRecurse) { $invokeParams.Recurse=$true }
                    if ($currentInlineFilePaths) { $invokeParams.InlineFilePaths=$currentInlineFilePaths }
                }

                # Use [Math]::Floor for integer turn numbers in debug log
                $turnNumberForDebug = [Math]::Floor($conversationHistory.Count / 2) + 1
                Write-Host "[DEBUG] Sending Prompt (Turn $turnNumberForDebug):`n$($invokeParams.Prompt)$($mediaAddedThisTurn ? "`n(With Media)" : "`n")" -F DarkYellow; Write-Host "Gemini thinking..." -F DarkGray
                
                try { $apiResult = Invoke-GeminiApi @invokeParams; $lastApiResult = $apiResult }
                catch { Write-Error "Critical error during Invoke-GeminiApi: $($_.Exception.Message)"; $apiResult = $null; $lastApiResult = $null }
                finally { Write-Host "`r".PadRight($Host.UI.RawUI.WindowSize.Width - 1); Write-Host "`r"-NoNewline }

                # Process-ApiResult should return an ArrayList
                $conversationHistory = Process-ApiResult -ApiResult $apiResult -CurrentPromptInput $currentPromptInput -SessionConfig $sessionConfig -ConversationHistory $conversationHistory
                $mediaAddedThisTurn = $false
                Write-Host "---" -F Cyan
            }
        }
    } finally {
        Write-Host "`nExiting Gemini chat session." -F Cyan
        if ($globalRenameErrors.Count -gt 0) { Write-Warning "$($globalRenameErrors.Count) rename error(s):"; $globalRenameErrors |% { Write-Warning "- $_" } }
        if ($globalMetadataErrors.Count -gt 0) { Write-Warning "$($globalMetadataErrors.Count) metadata error(s):"; $globalMetadataErrors |% { Write-Warning "- $_" } }
        if ($sessionConfig.CsvOutputFile -and $conversationHistory -and $conversationHistory.Count -gt 0) {
            try { Save-ChatToCsv -ConversationHistory $conversationHistory -CsvOutputFile $sessionConfig.CsvOutputFile }
            catch { Write-Error "Failed to save CSV: $($_.Exception.Message)" }
        } elseif ($sessionConfig.CsvOutputFile) { Write-Warning "CSV export skipped: History empty or null." }
        if ($isVerboseSwitchPresent) { $VerbosePreference = $originalVerbosePreference }
    }
    return $conversationHistory
}

Write-Verbose "Start-GeminiChat.ps1 loaded and function defined."
