--- /dev/null
+++ b/c:/BSC_Analytics/PowerShell/Gemini AI/README.md
@@ -0,0 +1,171 @@
+# Gemini PowerShell Chat & Media Processor
+
+This PowerShell script (`Start-GeminiChat`) provides a powerful interface to interact with Google's Gemini AI models. It supports conversational chat, processing local media files (images, videos, audio, documents) one-by-one, automatically renaming and updating metadata based on AI analysis, and generating images using Vertex AI.
+
+## Features
+
+*   **Interactive Chat:** Engage in multi-turn conversations with Gemini models.
+*   **Initial Media Processing:**
+    *   Process a folder of media files (`-MediaFolder`) using an initial prompt (`-StartPrompt`).
+    *   Files are processed individually, sending each file with the prompt to Gemini.
+*   **Metadata Modification (`-ModifyFiles`):**
+    *   **Requires ExifTool.**
+    *   Parses Gemini's response (expecting specific formats like `Name:`, `Description:`, `Rating:`, `Tags:`, `Location:`).
+    *   **Renaming:** Automatically renames files based on parsed `Name`, `Location` (optional), and `Rating` (optional).
+    *   **Metadata Updates:** Updates various metadata fields based on parsed info and specified `-Update*` switches (e.g., `-UpdateTitle`, `-UpdateTags`, `-UpdateDescription`).
+    *   **Confirmation:** Use `-Confirm` to review proposed changes before they are applied.
+*   **Location Processing (`-UpdateLocation`):**
+    *   **Requires ExifTool.**
+    *   Reads GPS coordinates from image files (JPG, HEIC, TIFF).
+    *   Appends coordinates to the prompt, asking Gemini for the location (City, State, Country).
+    *   Parses the `Location:` field from the response.
+    *   Includes the location in the filename (if `-ModifyFiles` is active).
+    *   Writes City, State, and Country metadata (if `-ModifyFiles` is active).
+*   **Sidecar File Generation:**
+    *   Save AI-generated summaries (`-SaveSummaryFile`) or chapters (`-SaveChaptersFile`) to separate `.txt` files alongside the original media.
+*   **Vertex AI Image Generation:**
+    *   Generate images directly from the chat using the `/generate <prompt>` or `/image <prompt>` command (requires Google Cloud SDK setup).
+*   **Configuration:** Control API model, generation parameters, timeouts, retries, and processing delays.
+*   **Logging:** Append prompts, responses, and actions to an output file (`-OutputFile`).
+
+## Dependencies
+
+1.  **PowerShell:** Version 5.1 or later (Windows PowerShell) or PowerShell 7+.
2.  **ExifTool:** **Required** for all metadata modification (`-ModifyFiles`, `-Update*` switches) and GPS reading (`-UpdateLocation`).
    *   Download from https://exiftool.org/.
    *   Ensure `exiftool.exe` is either in your system's PATH environment variable or provide the full path using the `-ExifToolPath` parameter.
+3.  **Google Cloud SDK (`gcloud`):** **Required** *only* if using the `/generate` or `/image` command for Vertex AI image generation.
+    *   Install from https://cloud.google.com/sdk/docs/install.
+    *   Authenticate: Run `gcloud auth login` and `gcloud auth application-default login`.
+    *   Set Project: Run `gcloud config set project YOUR_PROJECT_ID`.
+    *   Enable APIs: Ensure the "Vertex AI API" is enabled in your Google Cloud project.
+
+## Setup
+
+1.  **Clone/Download:** Get the script file (`Gemini_Chat_Analyze_Modify_Metadata_Media_Local_Files_Description_ExifTool_Vertex_Image_Gen.ps1`).
+2.  **Install ExifTool:** Follow the instructions on the ExifTool website. Add it to your PATH or note the full path to `exiftool.exe`.
+3.  **(Optional) Install Google Cloud SDK:** If you plan to use image generation, install and configure `gcloud` as described above.
+4.  **API Key:** Obtain a Gemini API Key from Google AI Studio.
+    *   **Recommended:** Set the API key as an environment variable:
+        ```powershell
+        $env:GEMINI_API_KEY = "YOUR_API_KEY_HERE"
+        ```
+    *   Alternatively, you can pass it directly using the `-ApiKey` parameter (less secure).
+5.  **Load Script:** Open PowerShell and load the script functions into your session:
+    ```powershell
+    . .\Gemini_Chat_Analyze_Modify_Metadata_Media_Local_Files_Description_ExifTool_Vertex_Image_Gen.ps1
+    ```
+
+## Parameters (`Start-GeminiChat`)
+
+*(Selected Parameters - see script's comment-based help for full details)*
+
+*   `-ApiKey <String>`: (Required) Your Gemini API Key (or set `$env:GEMINI_API_KEY`).
+*   `-Model <String>`: Gemini model ID (default: `gemini-1.5-pro-latest`).
+*   `-StartPrompt <String>`: Prompt used for initial file processing. **Required** if `-MediaFolder` is used. Should ask for `Name:`, `Description:`, `Rating:`, `Tags:`, etc.
+*   `-MediaFolder <String>`: Folder with media files for initial processing.
+*   `-RecurseFiles`: Search `-MediaFolder` recursively.
+*   `-ModifyFiles`: Enable renaming and metadata updates for initial files. **Requires ExifTool.**
+*   `-Confirm`: Require user confirmation before applying modifications (if `-ModifyFiles` is used).
+*   `-UpdateTitle`, `-UpdateAuthor`, `-UpdateSubject`, `-UpdateTags`, `-UpdateRating`, `-UpdateDescription`: Enable specific metadata updates. **Require `-ModifyFiles` and ExifTool.**
+*   `-AuthorName <String>`: Author name to use with `-UpdateAuthor`.
+*   `-UpdateLocation`: Enable GPS reading, AI location prompting, filename update, and location metadata writing. **Requires `-ModifyFiles` and ExifTool.**
+*   `-SaveSummaryFile`, `-SaveChaptersFile`: Save parsed Summary/Chapters to sidecar `.txt` files.
+*   `-ExifToolPath <String>`: Full path to `exiftool.exe` if not in PATH.
+*   `-OutputFile <String>`: Path to append conversation logs.
+*   `-FileDelaySec <Int32>`: Delay (seconds) between processing initial files.
+*   `-VertexProjectId <String>`, `-VertexLocationId <String>`, `-VertexDefaultOutputFolder <String>`: Required for `/generate` command.
+*   `-Verbose`: Enable detailed script output.
+
+## Usage Examples
+
+```powershell
+# Load the script first
+. .\Gemini_Chat_Analyze_Modify_Metadata_Media_Local_Files_Description_ExifTool_Vertex_Image_Gen.ps1
+
+# --- Configuration (Adjust Paths/Values) ---
+$myApiKey = $env:GEMINI_API_KEY # Or set directly: "YOUR_API_KEY..."
+$myMediaFolder = "C:\Path\To\Your\Media"
+$myLogFile = Join-Path -Path $myMediaFolder -ChildPath "gemini_chat_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
+$myAuthor = "Your Name"
+$myExifToolPath = "C:\path\to\exiftool.exe" # Only needed if not in PATH
+
+# Vertex AI Config (Optional)
+$vertexProjectID = "your-gcp-project-id"
+$vertexLocationId = "us-central1"
+$vertexOutput = Join-Path -Path $myMediaFolder -ChildPath "GeneratedImages"
+
+# Define your analysis prompt
+$analysisPrompt = @"
+Analyze the provided file and respond ONLY with the following numbered fields:
+1. Name: Suggest an emotional, descriptive filename (5-10 words, use underscores). Example: Name: Joyful_Golden_Retriever_Playing_Fetch_In_Sunny_Park
+2. Description: Write an engaging description (100-500 words). Example: Description: A vibrant scene unfolds as a golden retriever...
+3. Rating: Rate the file's overall quality (0-5). Example: Rating: 4
+4. Tags: List 30-50 specific keywords (main subject, elements, location, actions, concepts, style, format). Example: Tags: dog, golden retriever, park, playing, fetch, happy, sunny, green grass, outdoor, pet, animal, canine, action shot, horizontal
+5. Summary: (Only for video/audio) Provide a concise summary. Example: Summary: This video shows a dog playing fetch...
+6. Chapters: (Only for video/audio with distinct sections) Suggest chapter timestamps and titles. Example: Chapters: 00:00 Intro, 01:15 Fetch sequence, 03:40 Resting
+"@
+
+# --- Example 1: Process files, modify metadata/filenames (with confirmation), save sidecars ---
+if ($myApiKey -and (Test-Path $myMediaFolder)) {
+    Start-GeminiChat -ApiKey $myApiKey -Model 'gemini-1.5-flash-latest' `
+        -StartPrompt $analysisPrompt -MediaFolder $myMediaFolder `
+        -ModifyFiles -Confirm ` # Ask before applying changes
+        -UpdateTitle -UpdateAuthor -AuthorName $myAuthor -UpdateSubject -UpdateTags -UpdateRating -UpdateLocation -UpdateDescription `
+        -SaveSummaryFile -SaveChaptersFile `
+        -ExifToolPath $myExifToolPath -OutputFile $myLogFile -FileDelaySec 1 `
+        -VertexProjectId $vertexProjectID -VertexLocationId $vertexLocationId -VertexDefaultOutputFolder $vertexOutput `
+        -Verbose
+}
+
+# --- Example 2: Simple interactive chat only ---
+if ($myApiKey) {
+     Start-GeminiChat -ApiKey $myApiKey -Model 'gemini-1.5-flash-latest' -OutputFile $myLogFile -Verbose
+}
+
+# --- Example 3: Process files, save sidecars ONLY (no modifications) ---
+if ($myApiKey -and (Test-Path $myMediaFolder)) {
+    Start-GeminiChat -ApiKey $myApiKey -Model 'gemini-1.5-flash-latest' `
+        -StartPrompt $analysisPrompt -MediaFolder $myMediaFolder `
+        -SaveSummaryFile -SaveChaptersFile ` # Only save sidecars
+        -OutputFile $myLogFile -FileDelaySec 1 `
+        -Verbose
+}
+
+# --- Example 4: Interactive chat with image generation enabled ---
+# (Ensure gcloud SDK is installed and authenticated)
+if ($myApiKey -and $vertexProjectID) {
+    Start-GeminiChat -ApiKey $myApiKey -Model 'gemini-1.5-pro-latest' `
+        -VertexProjectId $vertexProjectID `
+        -VertexLocationId $vertexLocationId `
+        -VertexDefaultOutputFolder $vertexOutput `
+        -OutputFile $myLogFile -Verbose
+    # During the chat, type: /generate A futuristic cityscape at sunset
+}
+```
+
+## Notes
+
+*   **Metadata Overwriting:** When using `-ModifyFiles` and `-Update*` switches, existing metadata in the specified fields will generally be overwritten by the information parsed from the Gemini response. Tag clearing occurs before adding new tags if `-UpdateTags` is used.
+*   **ExifTool Dependency:** Metadata modification and GPS reading rely heavily on ExifTool. Ensure it's correctly installed and accessible.
+*   **API Costs:** Be aware of potential costs associated with using the Gemini API and Vertex AI, especially when processing many files or generating images.
+*   **Rate Limits:** The script includes basic retry logic for API rate limits (HTTP 429), but aggressive processing might still hit limits. Adjust `-FileDelaySec` if needed.
+*   **Error Handling:** The script includes error handling, but complex scenarios (corrupt files, network issues, unexpected API responses) might require manual intervention. Check the `-OutputFile` log for details.
+*   **Parsing Reliability:** The script relies on Gemini providing responses in the requested format (e.g., `Name: ...`, `Rating: ...`). Variations in the AI's output format might cause parsing failures for modifications. The prompt is crucial here.

