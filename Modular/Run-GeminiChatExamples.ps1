# Run-GeminiChatExamples.ps1
# Defines example variables and demonstrates how to call Start-GeminiChat.
# Loads the main Start-GeminiChat.ps1 script first.

#Requires -Version 5.1

# --- Load the Main Script ---
# Assumes Start-GeminiChat.ps1 is in the same directory.
try {
    Write-Verbose "Loading Start-GeminiChat script..."
    $mainScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "Start-GeminiChat.ps1"
    . $mainScriptPath
    # Verify function loaded
    if (-not (Get-Command 'Start-GeminiChat' -ErrorAction SilentlyContinue)) {
        throw "Start-GeminiChat function not found after dot-sourcing."
    }
    Write-Verbose "Start-GeminiChat script loaded successfully."
} catch {
    Write-Error "Failed to load Start-GeminiChat.ps1. Ensure it's in the same directory ($PSScriptRoot). Error: $($_.Exception.Message)"
    # Exit the example script if the main script can't be loaded
    exit 1
}

# --- Define Example Variables ---
Write-Host "`n--- Setting up Example Variables ---" -ForegroundColor Gray

# Define default values for example calls.
$examplePrompt = @"
No other text, Analyze the provided file:
1. Name: (Suggest emotional descriptive filename, 5-10 words, underscores for spaces)
2. Description: (Suggest emotional description, 100-500 words)
3. Rating: (Suggest 0-5 quality rating)
4. Tags: (Suggest 30-50 keywords: main subject, elements, location, actions, concepts, demographics, technical, format)
"@
$myMediaFolder = "G:\My Drive\All Life Matters\Videos\20250503_231754.mp4" # Use script's directory
$myLogFile = Join-Path $myMediaFolder "gemini_unified_log_v4.0.0.txt"
$myAuthor = "Steven Stoddard"
$vertexProjectID = "vertex-image-generation" # <-- IMPORTANT: Replace with your GCP Project ID or leave blank to be prompted
$vertexLocationId = "us-central1" # Common default
$vertexDefaultOutputFolder = Join-Path $myMediaFolder "GeneratedImages"
$ExifToolPath = "" # Leave blank to search PATH, or specify full path e.g., "C:\Tools\exiftool.exe"

# Create example folders if they don't exist
 if (-not (Test-Path $myMediaFolder)) { Write-Host "Creating example folder: $myMediaFolder"; New-Item -Path $myMediaFolder -ItemType Directory -Force > $null }
 if (-not (Test-Path $vertexDefaultOutputFolder)) { Write-Host "Creating example folder: $vertexDefaultOutputFolder"; New-Item -Path $vertexDefaultOutputFolder -ItemType Directory -Force > $null }
# Optional: Create a dummy file for testing Example 1
 if (-not (Get-ChildItem -Path $myMediaFolder -Filter *.jpg -File)) { Set-Content -Path (Join-Path $myMediaFolder "test.jpg") -Value "dummy jpeg content" -Force }


# --- API Key Setup ---
# Prioritize environment variable, then prompt if needed.
$apiKey = $env:GEMINI_API_KEY
if ([string]::IsNullOrWhiteSpace($apiKey)) {
    Write-Warning "`$env:GEMINI_API_KEY not set. You will be prompted by Start-GeminiChat."
    $apiKey = $null # Explicitly set to $null so parameter binding doesn't fail
} else { # API Key WAS found in environment variable
    Write-Host "Using API Key from `$env:GEMINI_API_KEY." -ForegroundColor DarkGray
}

Write-Host "------------------------------------" -ForegroundColor Gray


# --- Example Execution Options ---
# Uncomment ONE of the blocks below to run an example.

# Example 1: Process files with modifications
<#
Write-Host "`n--- Running Example 1: File Processing ---`n" -F Yellow
if (Test-Path $myMediaFolder) {
    Start-GeminiChat -ApiKey $apiKey -Model 'gemini-1.5-flash' `
        -StartPrompt $examplePrompt -MediaFolder $myMediaFolder -ModifyFiles -Confirm `
        -UpdateTitle -UpdateAuthor -AuthorName $myAuthor -UpdateTags -UpdateRating -UpdateLocation `
        -ExifToolPath $ExifToolPath -OutputFile $myLogFile -FileDelaySec 0 -Verbose `
        -ResultsCsvFile (Join-Path $myMediaFolder "parsed_results.csv") `
        -CsvOutputFile (Join-Path $myMediaFolder "chat_history_files.csv")
} else { Write-Warning "Media folder '$myMediaFolder' not found for Example 1." }
#>

# Example 2: Interactive chat with Vertex AI configured (or prompts if needed)
#<#
Write-Host "`n--- Running Example 2: Interactive Chat + Vertex AI ---`n" -F Yellow
Start-GeminiChat -ApiKey $apiKey -Model 'gemini-1.5-flash' `
    -VertexProjectId $vertexProjectID `
    -VertexLocationId $vertexLocationId `
    -VertexDefaultOutputFolder $vertexDefaultOutputFolder `
    -VertexImageModel "imagen-3.0-fast-generate-001" `
    -OutputFile $myLogFile -Verbose `
    -CsvOutputFile (Join-Path $myMediaFolder "chat_history_gen.csv")
# Chat commands: /generate A futuristic cityscape | /imagemodel imagen-3.0-generate-002 | /generate_from ./Review_Photos/test.jpg
#>

# Example 3: Basic interactive chat
# <#
# Write-Host "`n--- Running Example 3: Basic Interactive Chat ---`n" -F Yellow
# Start-GeminiChat -ApiKey $apiKey -Model 'gemini-1.5-flash' -Verbose
# #>

Write-Host "`nExample script finished. If no example was uncommented, nothing was executed." -ForegroundColor Green
