#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Permissions-Licenses-Revoke
# Revoke license from account
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
    #region Verify account reference
    $actionMessage = "verifying account reference"
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw "The account reference could not be found"
    }
    #endregion Verify account reference

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

    #region Revoke permission from account
    # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/user-assignlicense?view=graph-rest-1.0&tabs=http
    $actionMessage = "revoking license [$($actionContext.PermissionDisplayName)] with skuid [$($actionContext.References.Permission.reference)] from account"

    $revokePermissionBody = @{
        addLicenses    = $null
        removeLicenses = @($($actionContext.References.Permission.reference))
    }
            
    $baseUri = "https://graph.microsoft.com/"
    $revokePermissionSplatParams = @{
        Uri         = "$($baseUri)/v1.0/users/$($actionContext.References.Account)/assignLicense"
        Headers     = $headers
        Method      = "POST"
        Body        = ($revokePermissionBody | ConvertTo-Json -Depth 10)
        Verbose     = $false
        ErrorAction = "Stop"
    }

    if (-Not($actionContext.DryRun -eq $true)) {
        Write-Verbose "SplatParams: $($revokePermissionSplatParams | ConvertTo-Json)"

        $revokedPermission = Invoke-RestMethod @revokePermissionSplatParams

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Revoked license [$($actionContext.PermissionDisplayName)] with skuid [$($actionContext.References.Permission.reference)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                IsError = $false
            })
    }
    else {
        Write-Warning "DryRun: Would revoke license [$($actionContext.References.Permission.reference)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
    }
    #endregion Revoke permission from account
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    # Since the error message for removing a license when the user does not have that license is a 400 (bad request), we cannot check on a code or type
    # this may result in an incorrect check when the error messages are in any other language than english, please change this accordingly
    if ($auditMessage -like "*User does not have a corresponding license*") {
        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Skipped revoking license [$($actionContext.PermissionDisplayName)] with skuid [$($actionContext.References.Permission.reference)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: User does not have the corresponding license."
                IsError = $false
            })
    }
    # Since the error message for removing a license that does not exist for the company is a 400 (bad request), we cannot check on a code or type
    # this may result in an incorrect check when the error messages are in any other language than english, please change this accordingly
    elseif ($auditMessage -like "*License $($pRef.skuId) does not correspond to a valid company License*") {
        $auditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Skipped revoking license [$($actionContext.PermissionDisplayName)] with skuid [$($actionContext.References.Permission.reference)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: License does not correspond to a valid company license."
                IsError = $false
            }) 
    }
    else {
        Write-Warning $warningMessage

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = $auditMessage
                IsError = $true
            })
    }
}
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if ($outputContext.AuditLogs.IsError -contains $true) {
        $outputContext.Success = $false
    }
    else {
        $outputContext.Success = $true
    }
}
