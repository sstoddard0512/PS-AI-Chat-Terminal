# Start-GeminiChat.ps1
# Main script file containing the Start-GeminiChat function.
# Orchestrates the chat session by calling helper functions from other files.

#Requires -Version 5.1
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
    . "$PSScriptRoot\CoreUtils.ps1"
    . "$PSScriptRoot\GeminiApiUtils.ps1"
    . "$PSScriptRoot\VertexApiUtils.ps1"
    . "$PSScriptRoot\FileProcessingUtils.ps1"
    . "$PSScriptRoot\ChatUtils.ps1"
    Write-Verbose "Helper modules loaded."
} catch {
    Write-Error "Failed to load required helper scripts. Ensure CoreUtils.ps1, GeminiApiUtils.ps1, VertexApiUtils.ps1, FileProcessingUtils.ps1, and ChatUtils.ps1 are in the same directory as Start-GeminiChat.ps1. Error: $($_.Exception.Message)"
    return # Stop script execution if helpers can't be loaded
}

# --- Main Chat Function ---
function Start-GeminiChat {
    [CmdletBinding()]
    param(
        # --- Parameters (identical to original script v3.5.11) ---
        [Parameter(HelpMessage = "Your Google Gemini API Key.")] [string]$ApiKey,
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
        Write-Host "API Key required." -F Yellow; try { $secKey = Read-Host "Enter Google Gemini API Key" -AsSecureString; if($secKey.Length -gt 0){$bstr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secKey);$ApiKey=[Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr);[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)}else{Write-Error "API Key empty.";return} } catch { Write-Error "Failed read API Key: $($_.Exception.Message)"; return }
        $PSCmdlet.MyInvocation.BoundParameters['ApiKey'] = $ApiKey # Update bound params if prompted
    }

    # --- Initialize Session ---
    $sessionConfig = Initialize-GeminiChatSession -BoundParameters $PSCmdlet.MyInvocation.BoundParameters -Invocation $PSCmdlet.MyInvocation
    if (-not $sessionConfig) { Write-Error "Session initialization failed."; return }

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
            $mediaAddedThisTurn = $false

            # --- First Turn Logic ---
            if ($isFirstTurn) {
                $isFirstTurn = $false
                if ($sessionConfig.MediaFolder) {
                    if (Process-InitialMediaFiles -SessionConfig $sessionConfig -ApiKey $ApiKey -StartPrompt $StartPrompt -GlobalRenameErrors $globalRenameErrors -GlobalMetadataErrors $globalMetadataErrors) { continue }
                    else { Write-Warning "Initial file processing issue. Proceeding interactively." }
                } elseif ($StartPrompt) { $currentPromptInput = $StartPrompt; Write-Host "`nYou (Start): $currentPromptInput" -F White }
                else { $currentPromptInput = Get-ChatInput -SessionConfig $sessionConfig -IsFirstInteractiveTurn $true; if ([string]::IsNullOrWhiteSpace($currentPromptInput) -or $currentPromptInput.Trim() -eq '/exit') { break } }
            } else { # Subsequent Turns
                $currentPromptInput = Get-ChatInput -SessionConfig $sessionConfig -IsFirstInteractiveTurn $false
                if ([string]::IsNullOrWhiteSpace($currentPromptInput) -or $currentPromptInput.Trim() -eq '/exit') { break }
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

            $currentPromptInput = if ($commandResult.PromptOverride -ne $null) { $commandResult.PromptOverride } else { $currentPromptInput }
            $mediaAddedThisTurn = $commandResult.MediaAdded
            if ($currentPromptInput.Trim() -eq '/clear') { $lastUserPrompt = $null; $lastApiResult = $null } # Clear retry state on /clear
            if ($commandResult.ExitSession) { break }
            if ($commandResult.SkipApiCall) { Write-Host "---" -F Cyan; continue }

            # --- Make API Call ---
            if ($currentPromptInput -ne $null) {
                $lastUserPrompt = $currentPromptInput
                $invokeParams = @{ ApiKey=$ApiKey; Model=$sessionConfig.Model; TimeoutSec=$sessionConfig.TimeoutSec; MaxRetries=$sessionConfig.MaxRetries; InitialRetryDelaySec=$sessionConfig.InitialRetryDelaySec; Prompt=$currentPromptInput; ConversationHistory=$conversationHistory }; if ($sessionConfig.GenerationConfig) { $invokeParams.GenerationConfig = $sessionConfig.GenerationConfig }
                if ($mediaAddedThisTurn) { if ($currentImageFolder) { $invokeParams.ImageFolder=$currentImageFolder }; if ($currentVideoFolder) { $invokeParams.VideoFolder=$currentVideoFolder }; if ($currentRecurse) { $invokeParams.Recurse=$true }; if ($currentInlineFilePaths) { $invokeParams.InlineFilePaths=$currentInlineFilePaths } }
                $turnNumber = ($conversationHistory.Count / 2) + 1; $debugMsg = "[DEBUG] Sending Prompt (Turn $turnNumber):`n$($invokeParams.Prompt)$($mediaAddedThisTurn ? "`n(With Media)" : "`n")"
                Write-Host $debugMsg -F DarkYellow; Write-Host "Gemini thinking..." -F DarkGray
                $timerJob = Start-Job {Start-Sleep 999}; try { $apiResult = Invoke-GeminiApi @invokeParams; $lastApiResult = $apiResult } finally { Stop-Job $timerJob -EA SilentlyContinue; Remove-Job $timerJob -Force -EA SilentlyContinue; Write-Host "`r".PadRight($Host.UI.RawUI.WindowSize.Width - 1); Write-Host "`r"-NoNewline }
                $conversationHistory = Process-ApiResult -ApiResult $apiResult -CurrentPromptInput $currentPromptInput -SessionConfig $sessionConfig -ConversationHistory $conversationHistory
                $mediaAddedThisTurn = $false # Reset after processing
                Write-Host "---" -F Cyan
            }
        } # End while
    } finally {
        if ($globalRenameErrors.Count -gt 0) { Write-Warning "$($globalRenameErrors.Count) rename error(s):"; $globalRenameErrors |% { Write-Warning "- $_" } }
        if ($globalMetadataErrors.Count -gt 0) { Write-Warning "$($globalMetadataErrors.Count) metadata error(s):"; $globalMetadataErrors |% { Write-Warning "- $_" } }
        if ($sessionConfig.CsvOutputFile -and $conversationHistory.Count -gt 0) { Save-ChatToCsv -ConversationHistory $conversationHistory -CsvOutputFile $sessionConfig.CsvOutputFile } elseif ($sessionConfig.CsvOutputFile) { Write-Warning "Final CSV export skipped: History empty." }
        Write-Host "`nExiting Gemini chat session." -F Cyan
        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose "[Start-GeminiChat] Restoring original `$VerbosePreference ('$originalVerbosePreference')."; $VerbosePreference = $originalVerbosePreference }
    }
    return $conversationHistory
}

Write-Verbose "Start-GeminiChat.ps1 loaded and function defined."