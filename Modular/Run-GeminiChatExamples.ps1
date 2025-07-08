# Run-GeminiChatExamples.ps1
# Defines example variables and demonstrates how to call Start-GeminiChat.
# Loads the main Start-GeminiChat.ps1 script first.

#Requires -Version 7

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
1. Name: (Suggest emotional descriptive filename, 5 words, underscores for spaces)
2. Description: (Suggest emotional description, 100-500 words)
3. Rating: (Suggest 0-5 quality rating)
4. Tags: (Suggest 30-50 keywords: main subject, elements, location, actions, concepts, demographics, technical, format)
"@
# $media can be a file or folder path
$media = ""
 
# If $media was left empty (not specified by the user editing this script),
# create a "Media" folder in the script's root directory and use that.
if ([string]::IsNullOrWhiteSpace($media)) {
    $defaultMediaRootFolder = Join-Path -Path $PSScriptRoot -ChildPath "Media"
    Write-Verbose "Media path not specified. Attempting to use/create default media folder: '$defaultMediaRootFolder'"

    if (-not (Test-Path -LiteralPath $defaultMediaRootFolder -PathType Container)) {
        try {
            Write-Host "Creating default media folder: $defaultMediaRootFolder" -ForegroundColor Gray
            New-Item -Path $defaultMediaRootFolder -ItemType Directory -Force -ErrorAction Stop > $null
            $media = $defaultMediaRootFolder # Set $media if creation is successful
        } catch {
            Write-Error "Failed to create default media folder '$defaultMediaRootFolder'. Error: $($_.Exception.Message)"
            Write-Warning "Falling back to using script's root directory '$PSScriptRoot' as media path due to folder creation error."
            $media = $PSScriptRoot # Fallback if creation fails
        }
    } else {
        # Folder already exists, so use it
        $media = $defaultMediaRootFolder
        Write-Verbose "Default media folder '$defaultMediaRootFolder' already exists. Using it."
    }
}

# Determine the parent directory for logs and generated files
$mediaDirectory = $null # Initialize to null

if (-not [string]::IsNullOrWhiteSpace($media)) {
    if (Test-Path -LiteralPath $media -PathType Container) {
        $mediaDirectory = $media
        Write-Verbose "Media '$media' is a container. Using it as mediaDirectory."
    } elseif (Test-Path -LiteralPath $media -PathType Leaf) {
        Write-Verbose "Media '$media' is a file. Attempting to get its parent directory..."
        try {
            $resolvedMediaPath = Resolve-Path -LiteralPath $media -ErrorAction Stop
            # $resolvedMediaPath should be non-null here if Resolve-Path didn't throw
            $parentDir = [System.IO.Path]::GetDirectoryName($resolvedMediaPath.ProviderPath)
            if ([string]::IsNullOrWhiteSpace($parentDir)) {
                 Write-Verbose "  .NET GetDirectoryName for '$($resolvedMediaPath.ProviderPath)' failed or returned empty. Trying Split-Path..."
                 $parentDir = Split-Path -LiteralPath $resolvedMediaPath.ProviderPath -Parent -ErrorAction SilentlyContinue
            }
            
            if (-not [string]::IsNullOrWhiteSpace($parentDir)) {
                $mediaDirectory = $parentDir
                Write-Verbose "Determined parent directory for '$media': '$mediaDirectory'"
            } else {
                Write-Warning "Could not determine parent directory for file '$media'."
            }
        } catch {
            Write-Warning "Failed to determine parent directory for '$media'. Error: $($_.Exception.Message)"
            # $mediaDirectory remains $null, allowing fallback
        }
    } else {
        # $media is specified, but it's not an existing file or folder
        Write-Warning "Media path '$media' does not exist or is not a valid file/folder."
    }
} else {
    Write-Verbose "No media path specified. MediaDirectory will be defaulted."
}

# If mediaDirectory was not determined from $media (i.e., it's still null or empty),
# default to the current working directory.
if ([string]::IsNullOrWhiteSpace($mediaDirectory)) {
    Write-Verbose "MediaDirectory not determined from media path or media path was invalid. Defaulting to current working directory."
    $mediaDirectory = (Get-Location).Path
}

# Final check for a valid mediaDirectory before proceeding
if ([string]::IsNullOrWhiteSpace($mediaDirectory)) { Write-Error "Could not determine a valid media directory (even after attempting to default). Cannot proceed."; exit 1 }

# Define log file paths based on the determined directory
$mediaLogFile = Join-Path $mediaDirectory "gemini_media_processing_log_v4.0.0.txt" # Log for initial media processing (used by -OutputFile)
$logFile = Join-Path $mediaDirectory "gemini_interactive_chat_log_v4.0.0.txt" # Log for interactive chat (used by -LogFile)

# Other example variables
$author = "Steven Stoddard"
$vertexProjectID = "vertex-image-generation" # <-- IMPORTANT: Replace with your GCP Project ID or leave blank to be prompted
$vertexLocationId = "us-central1" # Common default, often has more models available
$vertexDefaultOutputFolder = Join-Path $mediaDirectory "GeneratedImages" # Use the directory path
$ExifToolPath = "" # Leave blank to search PATH, or specify full path e.g., "C:\Tools\exiftool.exe"

# Create example folders if they don't exist
 if (-not (Test-Path $mediaDirectory)) { Write-Host "Creating media directory: $mediaDirectory"; New-Item -Path $mediaDirectory -ItemType Directory -Force > $null }
 if (-not (Test-Path $vertexDefaultOutputFolder)) { Write-Host "Creating example folder: $vertexDefaultOutputFolder"; New-Item -Path $vertexDefaultOutputFolder -ItemType Directory -Force > $null }
# Optional: Create a dummy file for testing Example 1
 if (-not (Get-ChildItem -Path $mediaDirectory -Filter *.jpg -File)) { Set-Content -Path (Join-Path $mediaDirectory "test.jpg") -Value "dummy jpeg content" -Force }


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
# <#
# Write-Host "`n--- Running Example 1: File Processing ---`n" -F Yellow
# if (Test-Path -LiteralPath $media -PathType Container) { # Only run if $media is a folder (this $media is the folder for -MediaFolder)
   # Start-GeminiChat -ApiKey $apiKey -Model 'gemini-1.5-flash' -StartPrompt $examplePrompt -MediaFolder $media -ModifyFiles -Confirm -Media $media -UpdateTitle -UpdateAuthor -AuthorName $author -UpdateTags -UpdateRating -UpdateLocation  -ExifToolPath $ExifToolPath -OutputFile $mediaLogFile -FileDelaySec 0 -Verbose -ResultsCsvFile (Join-Path $mediaDirectory "parsed_results.csv") -CsvOutputFile (Join-Path $mediaDirectory "chat_history_files.csv")
# } else { Write-Warning "Skipping Example 1 because '$media' is not a valid folder path." }
# #>

# Example 2: Interactive chat with Vertex AI configured (or prompts if needed)
# <# <-- REMOVE '#' if uncommenting
Write-Host "`n--- Running Example 2: Interactive Chat + Vertex AI ---`n" -F Yellow
Start-GeminiChat -ApiKey $apiKey -Model 'gemini-1.5-flash' -Media $media -VertexProjectId $vertexProjectID -VertexLocationId $vertexLocationId -VertexDefaultOutputFolder $vertexDefaultOutputFolder -VertexImageModel "imagen-3.0-fast-generate-001" -LogFile $logFile -CsvOutputFile (Join-Path $mediaDirectory "chat_history_gen.csv")
# Chat commands: /generate A futuristic cityscape | /imagemodel imagen-3.0-generate-002 | /generate_from ./Review_Photos/test.jpg
# #> <-- REMOVE '#' if uncommenting

# Example 3: Basic interactive chat
# <#
# Write-Host "`n--- Running Example 3: Basic Interactive Chat ---`n" -F Yellow
# Start-GeminiChat -ApiKey $apiKey -Model 'gemini-1.5-flash' -Media $media -LogFile $logFile -Verbose # Pass initial media path
# #>

Write-Host "`nExample script finished. If no example was uncommented, nothing was executed." -ForegroundColor Green
