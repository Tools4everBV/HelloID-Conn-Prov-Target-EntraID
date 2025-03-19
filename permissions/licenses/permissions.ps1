#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Permissions-Licenses-List
# List licenses as permissions
# PowerShell V2
#################################################
# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($actionContext.Configuration.isDebug) {
    $true { $VerbosePreference = "Continue" }
    $false { $VerbosePreference = "SilentlyContinue" }
}
$InformationPreference = "Continue"
$WarningPreference = "Continue"

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object] $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }

        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception -is [System.Net.WebException] -and $ErrorObject.Exception.Response) {
            $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
            if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                $httpErrorObj.ErrorDetails = $streamReaderResponse
            }
        }

        try {
            $errorObjectConverted = $httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop

            if ($errorObjectConverted.error_description) {
                $httpErrorObj.FriendlyMessage = $errorObjectConverted.error_description
            }
            elseif ($errorObjectConverted.error) {
                $httpErrorObj.FriendlyMessage = $errorObjectConverted.error.message
                if ($errorObjectConverted.error.code) {
                    $httpErrorObj.FriendlyMessage += " Error code: $($errorObjectConverted.error.code)."
                }
                if ($errorObjectConverted.error.details) {
                    if ($errorObjectConverted.error.details.message) {
                        $httpErrorObj.FriendlyMessage += " Details message: $($errorObjectConverted.error.details.message)"
                    }
                    if ($errorObjectConverted.error.details.code) {
                        $httpErrorObj.FriendlyMessage += " Details code: $($errorObjectConverted.error.details.code)."
                    }
                }
            }
            else {
                $httpErrorObj.FriendlyMessage = $ErrorObject
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }

        Write-Output $httpErrorObj
    }
}
#endregion functions

try {
    #region Create authorization headers
    $actionMessage = "creating access token"
    $createAccessTokenBody = @{
        grant_type    = "client_credentials"
        client_id     = $actionContext.Configuration.AppId
        client_secret = $actionContext.Configuration.AppSecret
        resource      = "https://graph.microsoft.com"
    }
    $createAccessTokenSplatParams = @{
        Uri         = "https://login.microsoftonline.com/$($actionContext.Configuration.TenantID)/oauth2/token"
        Headers     = $headers
        Body        = $createAccessTokenBody
        Method      = "POST"
        ContentType = "application/x-www-form-urlencoded"
        Verbose     = $false
        ErrorAction = "Stop"
    }
    $createAccessTokenResonse = Invoke-RestMethod @createAccessTokenSplatParams

    $actionMessage = "creating headers"
    $headers = @{
        "Accept"           = "application/json"
        "Authorization"    = "Bearer $($createAccessTokenResonse.access_token)"
        "Content-Type"     = "application/json;charset=utf-8"
        "Mwp-Api-Version"  = "1.0"
        "ConsistencyLevel" = "eventual"
    }
    #endregion Create authorization headers

    #region Get Microsoft Entra ID Licenses
    # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying Microsoft Entra ID Licenses"

    $microsoftEntraIDLicenses = [System.Collections.ArrayList]@()
    do {
        $baseUri = "https://graph.microsoft.com/"
        $getMicrosoftEntraIDLicensesSplatParams = @{
            Uri         = "$($baseUri)/v1.0/subscribedSkus"
            Headers     = $headers
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }
        if (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDLicensesResult.'@odata.nextLink')) {
            $getMicrosoftEntraIDLicensesSplatParams["Uri"] = $getMicrosoftEntraIDLicensesResult.'@odata.nextLink'
        }

        $getMicrosoftEntraIDLicensesResult = $null
        $getMicrosoftEntraIDLicensesResult = Invoke-RestMethod @getMicrosoftEntraIDLicensesSplatParams
    
        if ($getMicrosoftEntraIDLicensesResult.Value -is [array]) {
            [void]$microsoftEntraIDLicenses.AddRange($getMicrosoftEntraIDLicensesResult.Value)
        }
        else {
            [void]$microsoftEntraIDLicenses.Add($getMicrosoftEntraIDLicensesResult.Value)
        }
    } while (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDLicensesResult.'@odata.nextLink'))

    Write-Information "Queried Microsoft Entra ID Licenses. Result count: $(($microsoftEntraIDLicenses | Measure-Object).Count)"
    #endregion Get Microsoft Entra ID Licenses

    #region Send results to HelloID
    $microsoftEntraIDLicenses | ForEach-Object {
        # Shorten DisplayName to max. 100 chars
        $displayName = "License - $($_.skuPartNumber)"
        $displayName = $displayName.substring(0, [System.Math]::Min(100, $displayName.Length)) 
        
        $outputContext.Permissions.Add(
            @{
                displayName    = $displayName
                identification = @{
                    Reference = $_.skuId
                }
            }
        )
    }
    #endregion Send results to HelloID
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    # Set Success to false
    $outputContext.Success = $false

    # Required to write an error as the listing of permissions doesn't show auditlog
    Write-Error $auditMessage
}