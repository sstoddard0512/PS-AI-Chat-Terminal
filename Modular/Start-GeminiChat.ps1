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
# Ensure helper scripts are in the same directory or adjust paths accordingly.
try {
    Write-Verbose "Loading helper modules..."
    . (Join-Path -Path $PSScriptRoot -ChildPath "CoreUtils.ps1")
    . (Join-Path -Path $PSScriptRoot -ChildPath "GeminiApiUtils.ps1")
    . (Join-Path -Path $PSScriptRoot -ChildPath "VertexApiUtils.ps1")
    . (Join-Path -Path $PSScriptRoot -ChildPath "FileProcessingUtils.ps1")
    . (Join-Path -Path $PSScriptRoot -ChildPath "ChatUtils.ps1") # Ensure this line is present and correct
    Write-Verbose "Helper modules loaded."
} catch {
    # Critical error: Cannot proceed without helpers.
    Write-Error "Failed to load required helper scripts. Ensure CoreUtils.ps1, GeminiApiUtils.ps1, VertexApiUtils.ps1, FileProcessingUtils.ps1, and ChatUtils.ps1 are in the same directory as Start-GeminiChat.ps1. Error: $($_.Exception.Message)"
    return # Stop script execution if helpers can't be loaded
}

# --- Main Chat Function ---
function Start-GeminiChat {
    [CmdletBinding()]
    param(
        # --- Parameters (identical to original script v3.5.11) ---
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
        [Parameter(HelpMessage = "Optional file to append the interactive chat log and errors.")] [string]$LogFile, # <-- NEW PARAMETER
        [Parameter(HelpMessage="Google Cloud Project ID for Vertex AI Image Generation.")] [string]$VertexProjectId,
        [Parameter(HelpMessage="Google Cloud Location ID (e.g., 'us-central1') for Vertex AI.")] [string]$VertexLocationId,
        [Parameter(HelpMessage="Default output folder for Vertex AI generated images.")] [string]$VertexDefaultOutputFolder,
        [Parameter(HelpMessage="The Vertex AI Imagen model ID (e.g., 'imagegeneration@006').")] [string]$VertexImageModel = 'imagegeneration@006',
        [Parameter(HelpMessage="Optional file path to export the full conversation history as a CSV file upon exiting.")] [string]$CsvOutputFile, # Parameter for CSV export of chat
        [Parameter(HelpMessage="Optional file path to save the parsed Gemini results for each processed file as a CSV.")] [string]$ResultsCsvFile, # Parameter for CSV export of parsed results
        [Parameter(HelpMessage="Optional media path (file or folder) to be used as the initial context or for the first turn if -StartPrompt is also used. Can also be used by the /media command if no path is provided to it.")] [string]$Media,
        [Parameter(HelpMessage="[Switch] Attempt to compress video files using FFmpeg before uploading.")] [switch]$CompressMedia,
        [Parameter(HelpMessage="Optional. Full path to ffmpeg.exe if not in system PATH. Required if -CompressMedia is used.")] [string]$FFmpegPath,
        [Parameter(HelpMessage="FFmpeg compression preset ('fast', 'medium', 'slow'). 'fast' = lower quality/faster, 'slow' = higher quality/slower.")] [ValidateSet('fast', 'medium', 'slow')] [string]$CompressionPreset = 'medium'
    )

    # --- Verbose Preference Handling ---
    $originalVerbosePreference = $VerbosePreference
    $isVerboseSwitchPresent = $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose') # Check if -Verbose was used
    if ($isVerboseSwitchPresent) { $VerbosePreference = 'Continue'; Write-Host "[Start-GeminiChat] Verbose logging enabled." -ForegroundColor DarkGray }

    # --- API Key Check (Prompt if missing) ---
    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        Write-Host "API Key required." -F Yellow
        while ($true) {
            try {
                $secKey = Read-Host "Enter Google Gemini API Key" -AsSecureString
                if ($secKey.Length -gt 0) { $bstr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secKey); $ApiKey=[Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr); [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr); break } # Break loop on valid input
                Write-Warning "API Key cannot be empty. Please try again."
            } catch {
                # Critical error: Cannot proceed without API key if prompt fails.
                Write-Error "Failed read API Key: $($_.Exception.Message)"; return
            }
        }
        $PSCmdlet.MyInvocation.BoundParameters['ApiKey'] = $ApiKey # Update bound params if prompted
    }

    # --- Initialize Session ---
    # Pass the boolean state directly
    $sessionConfig = Initialize-GeminiChatSession -BoundParameters $PSCmdlet.MyInvocation.BoundParameters -Invocation $PSCmdlet.MyInvocation -IsVerbose $isVerboseSwitchPresent
    if (-not $sessionConfig) {
        # Critical error: Session setup failed (e.g., invalid paths, missing tools).
        Write-Error "Session initialization failed. Check previous error messages."; return
    }

    # --- Initialize Chat State ---
    $conversationHistory = @()
    $lastUserPrompt = $null
    $lastApiResult = $null
    $globalRenameErrors = [System.Collections.ArrayList]::new()
    $globalMetadataErrors = [System.Collections.ArrayList]::new()
    $isFirstTurn = $true

    # --- Main Chat Loop ---
    # Use a broad try/finally to ensure cleanup happens even if unexpected errors occur within the loop.
    try {
        while ($true) {
            # --- Reset Turn Variables ---
            $currentPromptInput = $null; $apiResult = $null
            $currentImageFolder = $null; $currentVideoFolder = $null; $currentRecurse = $false; $currentInlineFilePaths = $null
            $mediaAddedThisTurn = $false

            # --- First Turn Logic ---
            if ($isFirstTurn) {
                $isFirstTurn = $false
                if ($sessionConfig.MediaFolder) {
                    # Process-InitialMediaFiles handles its own errors internally and returns true/false
                    # If it returns false, we just fall through to the interactive prompt.
                    if (Process-InitialMediaFiles -SessionConfig $sessionConfig -ApiKey $ApiKey -StartPrompt $StartPrompt -GlobalRenameErrors $globalRenameErrors -GlobalMetadataErrors $globalMetadataErrors) { continue }
                    else { Write-Warning "Initial file processing issue or no files found. Proceeding interactively." }
                } elseif ($StartPrompt) { $currentPromptInput = $StartPrompt; Write-Host "`nYou (Start): $currentPromptInput" -F White }
                else {
                    # Get-ChatInput handles empty input and /back, returns /exit on error
                    $currentPromptInput = Get-ChatInput -SessionConfig $sessionConfig -IsFirstInteractiveTurn $true
                    if ($currentPromptInput -eq '/exit') { break } # Exit loop if Get-ChatInput had an error or user typed /exit
                }
            } else { # Subsequent Turns
                # Get-ChatInput handles empty input and /back, returns /exit on error
                $currentPromptInput = Get-ChatInput -SessionConfig $sessionConfig -IsFirstInteractiveTurn $false
                if ($currentPromptInput -eq '/exit') { break } # Exit loop if Get-ChatInput had an error or user typed /exit
            }

            # --- Handle Commands ---
            # Handle-ChatCommand should handle its internal errors and return appropriate flags.
            # Critical errors within command handlers (like failed Vertex config) should prevent API calls.
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
                -IsVerbose $isVerboseSwitchPresent # Pass verbose status directly

            # Check if Handle-ChatCommand returned null (shouldn't happen with latest fix, but safety check)
            if ($null -eq $commandResult) {
                Write-Error "Handle-ChatCommand returned an unexpected null value. Skipping turn."
                continue
            }

            $currentPromptInput = if ($commandResult.PromptOverride -ne $null) { $commandResult.PromptOverride } else { $currentPromptInput }
            $mediaAddedThisTurn = $commandResult.MediaAdded
            if ($currentPromptInput.Trim() -eq '/clear') { $lastUserPrompt = $null; $lastApiResult = $null } # Clear retry state on /clear
            if ($commandResult.ExitSession) { break } # Exit loop if command signals exit
            if ($commandResult.SkipApiCall) { Write-Host "---" -F Cyan; continue } # Skip API call if command handled the turn

            # --- Make API Call ---
            if ($currentPromptInput -ne $null) {
                $lastUserPrompt = $currentPromptInput
                # Prepare parameters for Invoke-GeminiApi
                $invokeParams = @{
                    ApiKey              = $ApiKey
                    Model               = $sessionConfig.Model
                    TimeoutSec          = $sessionConfig.TimeoutSec
                    MaxRetries          = $sessionConfig.MaxRetries
                    InitialRetryDelaySec= $sessionConfig.InitialRetryDelaySec
                    Prompt              = $currentPromptInput
                    ConversationHistory = $conversationHistory
                    # Pass compression settings from session config
                    CompressMedia       = $sessionConfig.CompressMedia
                    FFmpegPath          = $sessionConfig.FFmpegPath
                    CompressionPreset   = $sessionConfig.CompressionPreset
                }
                if ($sessionConfig.GenerationConfig) { $invokeParams.GenerationConfig = $sessionConfig.GenerationConfig }
                if ($mediaAddedThisTurn) {
                    if ($currentImageFolder) { $invokeParams.ImageFolder=$currentImageFolder }
                    if ($currentVideoFolder) { $invokeParams.VideoFolder=$currentVideoFolder }
                    if ($currentRecurse) { $invokeParams.Recurse=$true }
                    if ($currentInlineFilePaths) { $invokeParams.InlineFilePaths=$currentInlineFilePaths }
                }

                $turnNumber = ($conversationHistory.Count / 2) + 1
                $debugMsg = "[DEBUG] Sending Prompt (Turn $turnNumber):`n$($invokeParams.Prompt)$($mediaAddedThisTurn ? "`n(With Media)" : "`n")"
                Write-Host $debugMsg -F DarkYellow; Write-Host "Gemini thinking..." -F DarkGray

                # API call itself is wrapped in try/finally for cleanup, Invoke-GeminiApi handles internal retries/errors
                try {
                    $apiResult = Invoke-GeminiApi @invokeParams
                    $lastApiResult = $apiResult # Store result for /retry
                } catch {
                    # This catch block is unlikely to be hit unless Invoke-GeminiApi has a critical failure *before* returning.
                    Write-Error "Unexpected critical error during Invoke-GeminiApi call: $($_.Exception.Message)"
                    $apiResult = $null # Ensure apiResult is null
                    $lastApiResult = $null
                } finally {
                    # Clear the "Gemini thinking..." line regardless of success/failure
                    Write-Host "`r".PadRight($Host.UI.RawUI.WindowSize.Width - 1); Write-Host "`r"-NoNewline
                }

                # Process the result (handles success/failure logging)
                $conversationHistory = Process-ApiResult -ApiResult $apiResult -CurrentPromptInput $currentPromptInput -SessionConfig $sessionConfig -ConversationHistory $conversationHistory
                $mediaAddedThisTurn = $false # Reset after processing
                Write-Host "---" -F Cyan
            }
        } # End while
    } finally {
        # This block executes when the loop exits (via /exit, break, or an unhandled exception)
        Write-Host "`nExiting Gemini chat session." -F Cyan

        # Display any accumulated errors from file processing
        if ($globalRenameErrors.Count -gt 0) { Write-Warning "$($globalRenameErrors.Count) rename error(s) occurred during file processing:"; $globalRenameErrors |% { Write-Warning "- $_" } }
        if ($globalMetadataErrors.Count -gt 0) { Write-Warning "$($globalMetadataErrors.Count) metadata error(s) occurred during file processing:"; $globalMetadataErrors |% { Write-Warning "- $_" } }

        # Attempt to save CSV history
        if ($sessionConfig.CsvOutputFile -and $conversationHistory.Count -gt 0) {
            try {
                Save-ChatToCsv -ConversationHistory $conversationHistory -CsvOutputFile $sessionConfig.CsvOutputFile
            } catch {
                Write-Error "Failed to save final chat history to CSV '$($sessionConfig.CsvOutputFile)': $($_.Exception.Message)"
            }
        } elseif ($sessionConfig.CsvOutputFile) {
            Write-Warning "Final CSV export skipped: History empty."
        }

        # Restore original verbose preference
        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) {
            Write-Verbose "[Start-GeminiChat] Restoring original `$VerbosePreference ('$originalVerbosePreference')."
            $VerbosePreference = $originalVerbosePreference
        }
    }
    # Return the final history (might be useful if called from another script)
    return $conversationHistory
}

Write-Verbose "Start-GeminiChat.ps1 loaded and function defined."
