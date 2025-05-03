# VertexApiUtils.ps1
# Contains function for interacting with the Google Vertex AI Imagen API.

#Requires -Version 5.1
# Requires gcloud CLI to be installed and authenticated.

# Depends on CoreUtils.ps1 for Sanitize-Filename

# --- Vertex AI Image Generation Function ---
function Start-VertexImageGeneration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$ProjectId,
        [Parameter(Mandatory = $true)] [string]$LocationId,
        [Parameter(Mandatory = $true)] [string]$Prompt,
        [string]$NegativePrompt,
        [Parameter(Mandatory = $true)] [string]$OutputFolder,
        [ValidateRange(1, 8)] [int]$Count = 1,
        [string]$ModelId = 'imagegeneration@006',
        [string]$Size,
        [string]$OutputFileNameBase,
        [string]$AspectRatio,
        [int]$Seed
    )
    # ... (Start-VertexImageGeneration function body from original script v3.5.11 / modular v4.0.0) ...
    # (Ensure it uses Sanitize-Filename from CoreUtils.ps1)
    $gcloudPath = Get-Command gcloud -EA SilentlyContinue; if (-not $gcloudPath) { Write-Error "gcloud CLI not found in PATH."; return }
    Write-Verbose "Using gcloud: $($gcloudPath.Path)"
    Write-Verbose "Getting Vertex AI access token..."; $accessToken = $null
    try { $gcloudOutput=gcloud auth print-access-token --quiet 2>&1; if($LASTEXITCODE -ne 0){throw "gcloud failed: $($gcloudOutput -join ';')"}; $accessToken=$gcloudOutput; if(-not $accessToken){throw "Empty token."}; Write-Verbose "Token obtained." }
    catch { Write-Error "Failed get token: $($_.Exception.Message)"; return }
    try { if (-not (Test-Path -LiteralPath $OutputFolder -PathType Container)) { Write-Warning "Creating output folder: $OutputFolder"; New-Item -Path $OutputFolder -ItemType Directory -Force -EA Stop | Out-Null } }
    catch { Write-Error "Failed create output folder '$OutputFolder': $($_.Exception.Message)"; return }

    $apiUrl="https://${LocationId}-aiplatform.googleapis.com/v1/projects/${ProjectId}/locations/${LocationId}/publishers/google/models/${ModelId}:predict"; Write-Verbose "Vertex Endpoint: $apiUrl"
    $requestBody=@{instances=@(@{prompt=$Prompt});parameters=@{sampleCount=$Count}}
    if ($NegativePrompt) { $requestBody.parameters.negativePrompt = $NegativePrompt }
    if ($Size) { $dims=$Size -split 'x'; if($dims.Length -eq 2 -and $dims[0] -as [int] -and $dims[1] -as [int]){$requestBody.parameters.add('width',[int]$dims[0]);$requestBody.parameters.add('height',[int]$dims[1])}else{Write-Warning "Invalid Size '$Size'."}}
    if ($AspectRatio) { $requestBody.parameters.aspectRatio = $AspectRatio }
    if ($PSBoundParameters.ContainsKey('Seed')) { $requestBody.parameters.seed = $Seed }
    $headers = @{ "Authorization" = "Bearer $accessToken"; "Content-Type" = "application/json; charset=utf-8" }
    $requestBodyJson = $requestBody | ConvertTo-Json -Depth 5; Write-Verbose "Request Body: $requestBodyJson"

    Write-Host "Sending request to Vertex AI (Model: $ModelId)..." -F DarkGray; $response = $null
    try { $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $requestBodyJson -ContentType "application/json; charset=utf-8" -TimeoutSec 300 -EA Stop }
    catch { Write-Error "Vertex API call failed: $($_.Exception.Message)"; if($_.Exception.Response){try{$s=$_.Exception.Response.GetResponseStream();$r=New-Object IO.StreamReader($s);$eBody=$r.ReadToEnd();$r.Close();if($eBody){Write-Error "Error Body: $eBody"}}catch{Write-Warning "No error body."}}; return }

    if ($response?.predictions -is [array] -and $response.predictions.Count -gt 0) {
        Write-Host "Vertex API successful. Processing $($response.predictions.Count) image(s)..." -F Green
        $baseFileName = if ($OutputFileNameBase) { Sanitize-Filename -InputString $OutputFileNameBase } else { Sanitize-Filename -InputString $Prompt -MaxLength 50 } # Assumes CoreUtils loaded
        $imageIndex = 0; foreach ($prediction in $response.predictions) { $imageIndex++; if ($prediction.bytesBase64Encoded) { try { $bytes = [System.Convert]::FromBase64String($prediction.bytesBase64Encoded); $suffix = if($Count -gt 1 -or $response.predictions.Count -gt 1){"_$($imageIndex)"}else{""}; $outPath = Join-Path -Path $OutputFolder -ChildPath "$($baseFileName)${suffix}.png"; $cIdx=1;$origPath=$outPath; while(Test-Path -LiteralPath $outPath){$outPath=Join-Path $OutputFolder "$($baseFileName)${suffix}_$($cIdx).png";$cIdx++}; if($outPath -ne $origPath){Write-Warning "Collision, saving as '$outPath'."}; [IO.File]::WriteAllBytes($outPath,$bytes); Write-Host "Saved image: $outPath" -F DarkGreen; try { Invoke-Item -Path $outPath -EA Stop } catch { Write-Warning "Cannot open '$outPath': $($_.Exception.Message)" } } catch { Write-Warning "Failed save image $imageIndex`: $($_.Exception.Message)" } } else { Write-Warning "Prediction $imageIndex no base64 data." } }
    } else { Write-Warning "Vertex response unexpected."; Write-Verbose "Full Response: $($response|ConvertTo-Json -Depth 5)" }
}

Write-Verbose "VertexApiUtils.ps1 loaded."