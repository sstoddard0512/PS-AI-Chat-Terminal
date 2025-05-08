# VertexApiUtils.ps1
# Contains function for interacting with the Google Vertex AI Imagen API.

#Requires -Version 7
# Requires gcloud CLI to be installed and authenticated.

# Depends on CoreUtils.ps1 for Sanitize-Filename (or ensure the placeholder below is adequate/replaced)

# --- Vertex AI Image Generation Function ---
function Start-VertexImageGeneration {
    [CmdletBinding(SupportsShouldProcess = $true)] # Added SupportsShouldProcess for -WhatIf potential
    param(
        [Parameter(Mandatory = $true)] [string]$ProjectId,
        [Parameter(Mandatory = $true)] [string]$LocationId,
        [Parameter(Mandatory = $true)] [string]$Prompt,
        [string]$NegativePrompt,
        [Parameter(Mandatory = $true)] [string]$OutputFolder,
        [ValidateRange(1, 8)] [int]$Count = 1,
        [string]$ModelId = 'imagegeneration@006', # Example: imagegeneration@005, imagegeneration@006, etc.
        [string]$Size, # e.g., "1024x1024", "1536x1024" - specific model might have constraints
        [string]$OutputFileNameBase,
        [string]$AspectRatio, # e.g., "1:1", "16:9", "4:3" - specific model might have constraints
        [int]$Seed
    )

    Write-Verbose "[DEBUG Start-VertexImageGeneration] Function started. Verbose logging is active if this message is visible."

    # Check for critical Sanitize-Filename dependency again inside the function if not globally checked
    if (-not (Get-Command Sanitize-Filename -ErrorAction SilentlyContinue)) {
        Write-Error "CRITICAL: Sanitize-Filename function is not available. Please load CoreUtils.ps1 or ensure the function is defined."
        return
    }

    $gcloudPath = Get-Command gcloud -ErrorAction SilentlyContinue
    if (-not $gcloudPath) {
        Write-Error "gcloud CLI not found in PATH. Please ensure it is installed and accessible."
        return
    }
    Write-Verbose "Using gcloud: $($gcloudPath.Path)"

    Write-Verbose "Getting Vertex AI access token..."
    $accessToken = $null
    try {
        # Capture the raw output. This will be a string if one line, or array of strings if multiple.
        $gcloudRawOutput = gcloud auth print-access-token --quiet 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            $errorMsgText = if ($gcloudRawOutput -is [array]) { $gcloudRawOutput -join [Environment]::NewLine } else { $gcloudRawOutput }
            throw "gcloud auth print-access-token failed. Exit Code: $LASTEXITCODE. Output: $errorMsgText"
        }

        $tokenString = $null
        if ($gcloudRawOutput -is [array]) {
            # If it's an array (e.g., token + warnings), take the first non-empty line.
            if ($gcloudRawOutput.Count -gt 0) {
                $tokenString = ($gcloudRawOutput | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
            }
        }
        else {
            # If it's not an array, it should be the token string itself.
            $tokenString = $gcloudRawOutput
        }

        if ([string]::IsNullOrWhiteSpace($tokenString)) {
            $errorMsgText = if ($gcloudRawOutput -is [array]) { $gcloudRawOutput -join [Environment]::NewLine } else { $gcloudRawOutput }
            throw "Retrieved access token is empty or whitespace. Full gcloud output (if any): $errorMsgText"
        }
        
        $accessToken = $tokenString.Trim() # Now $tokenString is a string
        Write-Verbose "Token obtained successfully (first 10 chars): $($accessToken.Substring(0, [System.Math]::Min($accessToken.Length, 10)))..."
    }
    catch {
        Write-Error "[Start-VertexImageGeneration] Failed to get gcloud access token: $($_.Exception.Message)"
        # For debugging, it might be useful to see the type of $gcloudRawOutput if an error occurs before this point
        if ($PSBoundParameters.ContainsKey('Verbose') -and $gcloudRawOutput) { Write-Verbose "[DEBUG Start-VertexImageGeneration] Type of gcloudRawOutput: $($gcloudRawOutput.GetType().FullName); Value: $gcloudRawOutput" }
        return
    }

    try {
        if (-not (Test-Path -LiteralPath $OutputFolder -PathType Container)) {
            Write-Warning "Output folder '$OutputFolder' does not exist. Attempting to create it."
            if ($PSCmdlet.ShouldProcess($OutputFolder, "Create Directory")) {
                New-Item -Path $OutputFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Verbose "Output folder '$OutputFolder' created."
            } else {
                Write-Warning "Creation of output folder '$OutputFolder' skipped due to -WhatIf."
                return # Cannot proceed without output folder
            }
        }
    }
    catch {
        Write-Error "[Start-VertexImageGeneration] Failed to create or access output folder '$OutputFolder': $($_.Exception.Message)"
        return
    }
    
    $apiUrl = "https://$($LocationId)-aiplatform.googleapis.com/v1/projects/$($ProjectId)/locations/$($LocationId)/publishers/google/models/$($ModelId):predict"
    Write-Verbose "Vertex Endpoint: $apiUrl"

    $requestBody = @{
        instances  = @(@{ prompt = $Prompt })
        parameters = @{ sampleCount = $Count }
    }
    Write-Verbose "[Start-VertexImageGeneration] Using ProjectId: $ProjectId, LocationId: $LocationId, ModelId: $ModelId"

    if ($PSBoundParameters.ContainsKey('NegativePrompt') -and -not [string]::IsNullOrWhiteSpace($NegativePrompt)) {
        $requestBody.parameters.negativePrompt = $NegativePrompt
    }

    if ($PSBoundParameters.ContainsKey('Size') -and -not [string]::IsNullOrWhiteSpace($Size)) {
        $dims = $Size -split 'x'
        $parsedWidth = $dims[0] -as [int]
        $parsedHeight = $dims[1] -as [int]

        if ($dims.Length -eq 2 -and $null -ne $parsedWidth -and $null -ne $parsedHeight) {
            # API might have specific constraints (e.g. >0, multiples of 64). Assuming parse is enough here.
            $requestBody.parameters.add('width', $parsedWidth)
            $requestBody.parameters.add('height', $parsedHeight)
            Write-Verbose "Added size parameters: width=$parsedWidth, height=$parsedHeight"
        } else {
            Write-Warning "Invalid Size format or value in '$Size'. Expected 'widthxheight' with integer values (e.g., '1024x768'). Size parameter will be ignored."
        }
    }

    if ($PSBoundParameters.ContainsKey('AspectRatio') -and -not [string]::IsNullOrWhiteSpace($AspectRatio)) {
        $requestBody.parameters.aspectRatio = $AspectRatio
    }
    if ($PSBoundParameters.ContainsKey('Seed')) { # Seed can be 0, so check if parameter was explicitly passed
        $requestBody.parameters.seed = $Seed
    }

    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json; charset=utf-8"
    }
    $requestBodyJson = $requestBody | ConvertTo-Json -Depth 5
    Write-Verbose "Request Body: $requestBodyJson"

    Write-Host "Sending request to Vertex AI (Model: $ModelId)..." -ForegroundColor DarkGray
    $response = $null
    if (-not $PSCmdlet.ShouldProcess($apiUrl, "Invoke POST Request to Vertex AI Imagen API")) {
        Write-Warning "API call skipped due to -WhatIf."
        return
    }

    try {
        $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $requestBodyJson -ContentType "application/json; charset=utf-8" -TimeoutSec 300 -ErrorAction Stop
    }
    catch [System.Net.WebException] {
        $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
        $statusDesc = if ($_.Exception.Response) { $_.Exception.Response.StatusDescription } else { 'N/A' }
        $errorMsg = "[Start-VertexImageGeneration] Vertex API call failed: $($_.Exception.Message) (Status: $statusCode '$statusDesc')"
        Write-Error $errorMsg
        if ($_.Exception.Response) {
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $errorBody = $reader.ReadToEnd()
                $reader.Close() # Close reader
                $stream.Close() # Close stream
                if ($errorBody) {
                    Write-Warning "Error response body received from API (first 500 chars): $($errorBody.Substring(0, [System.Math]::Min($errorBody.Length, 500)))"
                } else {
                    Write-Warning "Response body was empty for the error."
                }
            }
            catch { Write-Warning "Could not read error response body: $($_.Exception.Message)" }
        } else { Write-Warning "No response object available in the exception." }
        return
    }
    catch {
        $exception = $_.Exception
        $errorMessage = "[Start-VertexImageGeneration] An unexpected error occurred during API call: $($exception.Message)"
        if ($exception.InnerException) {
            $errorMessage += " Inner Exception: $($exception.InnerException.Message)"
        }

        # Attempt to get more details if it's an HttpResponseException
        if ($exception -is [Microsoft.PowerShell.Commands.HttpResponseException]) {
            $httpResponse = $exception.Response
            $statusCode = $httpResponse.StatusCode
            $errorMessage += " (HTTP Status: $statusCode)"
            Write-Error $errorMessage # Write the error message with status code first

            # Try to get text content from the response
            try {
                $responseContentString = $null
                if ($httpResponse.Content) { # $httpResponse.Content is HttpContent
                    $responseContentString = $httpResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                }

                if (-not [string]::IsNullOrWhiteSpace($responseContentString)) {
                    # Log a snippet of the response content to the warning stream for better visibility
                    $snippet = $responseContentString.Substring(0, [System.Math]::Min($responseContentString.Length, 500))
                    Write-Warning "[Start-VertexImageGeneration] API Error Response Snippet (Status $statusCode):`n$snippet"
                } else {
                    Write-Warning "[Start-VertexImageGeneration] API Error (Status $statusCode) but response content was empty or could not be read as string."
                }
            } catch {
                Write-Warning "[Start-VertexImageGeneration] Could not read or process API error response content: $($_.Exception.Message)"
            }
        } else {
            Write-Error $errorMessage # For non-HTTP related errors
        }
        Write-Verbose "[Start-VertexImageGeneration] Full exception details for unexpected API call error: $($exception | Format-List * -Force | Out-String)"
        return
    }

    # Enhanced pre-check logging for the main 'if' condition
    $debug_predictionsExist = $false
    $debug_isPredictionsArray = $false
    $debug_predictionsCount = 0
    Write-Verbose "[Start-VertexImageGeneration] Evaluating main condition components..."
    if ($null -ne $response) {
        # Check if 'predictions' property exists on the $response object
        if ($response.PSObject.Properties.Name -contains 'predictions') {
            # Check if the 'predictions' property itself is not null
            if ($null -ne $response.predictions) {
                $debug_predictionsExist = $true # 'predictions' property exists and is not null
                $debug_isPredictionsArray = $response.predictions -is [array]
                if ($debug_isPredictionsArray) {
                    try { $debug_predictionsCount = $response.predictions.Count }
                    catch { Write-Warning "[Start-VertexImageGeneration] Error getting predictions count for debug log: $($_.Exception.Message)" }
                }
            } else {
                Write-Verbose "[Start-VertexImageGeneration] Debug: `$response.predictions is `$null."
            }
        } else {
            Write-Verbose "[Start-VertexImageGeneration] Debug: `$response does not have a 'predictions' property."
        }
    } else {
        Write-Verbose "[Start-VertexImageGeneration] Debug: `$response is `$null."
    }
    Write-Verbose "[Start-VertexImageGeneration] Debug pre-check values: predictionsExist=$debug_predictionsExist, isPredictionsArray=$debug_isPredictionsArray, predictionsCount=$debug_predictionsCount"

    if ($debug_predictionsExist -and $debug_isPredictionsArray -and $debug_predictionsCount -gt 0) {
        Write-Host "Vertex API successful. Processing $($response.predictions.Count) image(s)..." -ForegroundColor Green
        $baseFileNameToUse = if ($OutputFileNameBase) { Sanitize-Filename -InputString $OutputFileNameBase } else { Sanitize-Filename -InputString $Prompt -MaxLength 50 }
        
        $imageIndex = 0 # Initialize imageIndex before the loop for clarity
        foreach ($prediction in $response.predictions) {
            $imageIndex++
            $currentOutPath = $null # Initialize for potential use in catch block

            if ($prediction.bytesBase64Encoded) {
                try {
                    $bytes = [System.Convert]::FromBase64String($prediction.bytesBase64Encoded)
                    if ($bytes.Length -eq 0) {
                        Write-Warning "Image ${imageIndex}: API provided empty image data. File will not be saved with content."
                        continue # Skip to next prediction
                    }

                    $suffix = if ($Count -gt 1 -or $response.predictions.Count -gt 1) { "_$($imageIndex)" } else { "" }
                    $fileNameAttempt = "$($baseFileNameToUse)${suffix}.png" # Vertex usually returns PNG
                    $currentOutPath = Join-Path -Path $OutputFolder -ChildPath $fileNameAttempt
                    
                    # Handle filename collisions by appending _1, _2, etc.
                    $collisionIndex = 1
                    $originalPathForCollisionCheck = $currentOutPath
                    while (Test-Path -LiteralPath $currentOutPath -PathType Leaf) { # Check for existing file
                        $fileNameAttempt = "$($baseFileNameToUse)${suffix}_$($collisionIndex).png"
                        $currentOutPath = Join-Path -Path $OutputFolder -ChildPath $fileNameAttempt
                        $collisionIndex++
                    }
                    if ($currentOutPath -ne $originalPathForCollisionCheck) {
                        Write-Warning "Filename collision for '$originalPathForCollisionCheck'. Saving as '$currentOutPath'."
                    }

                    Write-Verbose "[Start-VertexImageGeneration] Attempting to write $($bytes.Length) bytes to '$currentOutPath'."
                    if ($PSCmdlet.ShouldProcess($currentOutPath, "Write Image File")) {
                        [System.IO.File]::WriteAllBytes($currentOutPath, $bytes)
                        Write-Verbose "[Start-VertexImageGeneration] Call to [IO.File]::WriteAllBytes for '$currentOutPath' completed."
                        Write-Host "Saved image: $currentOutPath" -ForegroundColor DarkGreen

                        # Pause briefly for filesystem to catch up before trying to open the file.
                        # This can help avoid "file not found" errors on some systems when opening immediately after writing.
                        Write-Verbose "Pausing for 1 second before attempting to open '$currentOutPath'..."
                        Start-Sleep -Seconds 1 

                        Write-Verbose "[Start-VertexImageGeneration] Checking existence of '$currentOutPath' with Test-Path."
                        if (Test-Path -LiteralPath $currentOutPath -PathType Leaf) {
                            Write-Verbose "Path '$currentOutPath' confirmed to exist. Attempting to open..."
                            try {
                                Invoke-Item -LiteralPath $currentOutPath -ErrorAction Stop
                                Write-Verbose "Invoke-Item completed for '$currentOutPath'."
                            }
                            catch {
                                Write-Error "Failed to automatically open '$currentOutPath': $($_.Exception.Message)"
                                Write-Verbose "Full exception details for Invoke-Item failure: $($_.Exception | Format-List * -Force | Out-String)"
                            }
                        } else {
                            Write-Error "File '$currentOutPath' was NOT FOUND by Test-Path after attempting to save. Possible causes: permissions, antivirus, filesystem sync delay, or the path is incorrect."
                            Write-Verbose "[Start-VertexImageGeneration] OutputFolder was '$OutputFolder'. BaseFileName was '$baseFileNameToUse'. Suffix was '$suffix'."
                        }
                    } else {
                         Write-Warning "Skipped writing image '$currentOutPath' due to -WhatIf."
                    }
                }
                catch {
                    $errMsg = "Failed to process or save image ${imageIndex}"
                    if ($currentOutPath) { $errMsg += " (intended for '$currentOutPath')" }
                    $errMsg += ": $($_.Exception.Message)"
                    Write-Warning $errMsg
                    Write-Verbose "[Start-VertexImageGeneration] Full exception during prediction processing (image $imageIndex): $($_.Exception | Format-List * -Force | Out-String)"
                }
            } else {
                Write-Warning "Prediction ${imageIndex}: API provided no 'bytesBase64Encoded' data."
            }
        } # End foreach prediction
    } else {
        # This 'else' block is entered if the main condition (now using $debug_*) is false.
        # The $debug_* variables logged just before the 'if' should explain why.
        Write-Verbose "[Start-VertexImageGeneration] Main condition for processing predictions was false (based on debug_predictionsExist, debug_isPredictionsArray, debug_predictionsCount)."
        
        # The original detailed diagnostics for the 'else' block are still useful here
        # to compare with the $debug_* variables if there's still a discrepancy.
        Write-Verbose "[Start-VertexImageGeneration] Entering original detailed diagnostics for 'else' block..."
        Write-Verbose "[Start-VertexImageGeneration] Is `$response null? $($null -eq $response)"
        if ($null -ne $response) {
            Write-Verbose "[Start-VertexImageGeneration] Type of `$response: $($response.GetType().FullName)"
            Write-Verbose "[Start-VertexImageGeneration] Does `$response have PSObject.Properties? $(if ($response.PSObject.Properties) { $response.PSObject.Properties.Count -gt 0 } else { $false })"
            Write-Verbose "[Start-VertexImageGeneration] Attempting to access `$response.predictions..."
            Write-Verbose "[Start-VertexImageGeneration] Is `$response.predictions null? $($null -eq $response.predictions)"
            if ($null -ne $response.predictions) {
                Write-Verbose "[Start-VertexImageGeneration] Type of `$response.predictions: $($response.predictions.GetType().FullName)"
                Write-Verbose "[Start-VertexImageGeneration] Is `$response.predictions an array? $($response.predictions -is [array])"
                $predictionCountForLog = $null # Initialize
                try {
                    $predictionCountForLog = $response.predictions.Count
                } catch { # Catch any error if .Count is not accessible
                    $predictionCountForLog = "(Error accessing count: $($_.Exception.Message.Split('.')[0]))"
                }
                Write-Verbose "[Start-VertexImageGeneration] Count of `$response.predictions (if accessible): $predictionCountForLog"
            }
        }
        
        $warningMessage = ""
        if ($null -eq $response) {
            $warningMessage = "Vertex API did not return a response (Invoke-RestMethod likely failed or returned null)."
        } elseif ($response.PSObject.Properties.Count -eq 0) { # Check for an empty PSCustomObject (parsed from "{}")
            $warningMessage = "Vertex API returned an empty JSON object. No image data received."
        } elseif ($null -eq $response.predictions) {
            $warningMessage = "Vertex API response did not contain a 'predictions' field or it was null. No image data."
        } elseif (-not ($response.predictions -is [array])) {
            $warningMessage = "Vertex API response 'predictions' field was not an array. No image data."
        } elseif ($response.predictions.Count -eq 0) {
            $warningMessage = "Vertex API response 'predictions' array was empty. No image data received."
        } else {
            # This case should ideally not be hit if the $debug_* variables correctly reflected the state
            # and led to this 'else' block.
            $warningMessage = "Vertex API response was unexpected or did not contain usable image data (Else block reached despite debug variables suggesting otherwise - check logic)."
        }
        Write-Warning $warningMessage
        Write-Verbose "Full Response: $($response | ConvertTo-Json -Depth 5)"
    }
}

Write-Verbose "VertexApiUtils.ps1 loaded."

# --- Example Usage (commented out) ---
# Make sure gcloud is authenticated and CoreUtils.ps1 (for Sanitize-Filename) is available or the placeholder is sufficient.
#
# Start-VertexImageGeneration -ProjectId "vertex-image-generation" -LocationId "us-central1" -Prompt "A futuristic cityscape at sunset, cinematic lighting" -NegativePrompt "blurry, ugly, deformed, watermark, text" -OutputFolder "C:\VertexImages" -Count 2 -ModelId "imagegeneration@006" -Size "1024x1024" -Seed 12345 -Verbose

# Start-VertexImageGeneration -ProjectId "your-gcp-project-id" `
# -LocationId "us-central1" `
# -Prompt "photo of a fluffy cat wearing a tiny hat" `
# -OutputFolder "C:\VertexImages\Cats" `
# -Count 1 `
# -AspectRatio "1:1" `
# -OutputFileNameBase "fluffy_cat_hat" `
# -Verbose
