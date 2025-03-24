#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Permissions-Groups-List
# List groups as permissions
# Currently only Microsoft 365 and Security groups are supported by the Microsoft Graph API: https://docs.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0
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

    #region Microsoft 365 Groups
    #region Get Microsoft Entra ID Microsoft 365 Groups
    # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying Microsoft Entra ID Microsoft 365 Groups"

    $microsoftEntraIDM365Groups = [System.Collections.ArrayList]@()
    do {
        $baseUri = "https://graph.microsoft.com/"
        $getMicrosoftEntraIDM365GroupsSplatParams = @{
            Uri         = "$($baseUri)/v1.0/groups?`$filter=groupTypes/any(c:c+eq+'Unified')&`$select=id,displayName,onPremisesSyncEnabled,groupTypes&`$top=999&`$count=true"
            Headers     = $headers
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }
        if (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDM365GroupsResult.'@odata.nextLink')) {
            $getMicrosoftEntraIDM365GroupsSplatParams["Uri"] = $getMicrosoftEntraIDM365GroupsResult.'@odata.nextLink'
        }

        $getMicrosoftEntraIDM365GroupsResult = $null
        $getMicrosoftEntraIDM365GroupsResult = Invoke-RestMethod @getMicrosoftEntraIDM365GroupsSplatParams
    
        if ($getMicrosoftEntraIDM365GroupsResult.Value -is [array]) {
            [void]$microsoftEntraIDM365Groups.AddRange($getMicrosoftEntraIDM365GroupsResult.Value)
        }
        else {
            [void]$microsoftEntraIDM365Groups.Add($getMicrosoftEntraIDM365GroupsResult.Value)
        }
    } while (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDM365GroupsResult.'@odata.nextLink'))

    Write-Information "Queried Microsoft Entra ID Microsoft 365 Groups. Result count: $(($microsoftEntraIDM365Groups | Measure-Object).Count)"
    #endregion Get Microsoft Entra ID Microsoft 365 Groups

    #region Send results to HelloID
    $microsoftEntraIDM365Groups | ForEach-Object {
        # Shorten DisplayName to max. 100 chars
        $displayName = "M365 Group - $($_.displayName)"
        $displayName = $displayName.substring(0, [System.Math]::Min(100, $displayName.Length)) 
        
        $outputContext.Permissions.Add(
            @{
                displayName    = $displayName
                identification = @{
                    Id = $_.id
                }
            }
        )
    }
    #endregion Send results to HelloID
    #endregion Microsoft 365 Groups

    #region Security Groups
    #region Get Microsoft Entra ID Security Groups
    # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying Microsoft Entra ID Security Groups"

    $microsoftEntraIDSecurityGroups = [System.Collections.ArrayList]@()
    do {
        $baseUri = "https://graph.microsoft.com/"
        $getMicrosoftEntraIDSecurityGroupsSplatParams = @{
            Uri         = "$($baseUri)/v1.0/groups?`$filter=NOT(groupTypes/any(c:c+eq+'DynamicMembership')) and onPremisesSyncEnabled eq null and mailEnabled eq false and securityEnabled eq true&`$select=id,displayName,onPremisesSyncEnabled,groupTypes&`$top=999&`$count=true"
            Headers     = $headers
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }
        if (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDSecurityGroupsResult.'@odata.nextLink')) {
            $getMicrosoftEntraIDSecurityGroupsSplatParams["Uri"] = $getMicrosoftEntraIDSecurityGroupsResult.'@odata.nextLink'
        }

        $getMicrosoftEntraIDSecurityGroupsResult = $null
        $getMicrosoftEntraIDSecurityGroupsResult = Invoke-RestMethod @getMicrosoftEntraIDSecurityGroupsSplatParams
    
        if ($getMicrosoftEntraIDSecurityGroupsResult.Value -is [array]) {
            [void]$microsoftEntraIDSecurityGroups.AddRange($getMicrosoftEntraIDSecurityGroupsResult.Value)
        }
        else {
            [void]$microsoftEntraIDSecurityGroups.Add($getMicrosoftEntraIDSecurityGroupsResult.Value)
        }
    } while (-not[string]::IsNullOrEmpty($getMicrosoftEntraIDSecurityGroupsResult.'@odata.nextLink'))

    Write-Information "Queried Microsoft Entra ID Security Groups. Result count: $(($microsoftEntraIDSecurityGroups | Measure-Object).Count)"
    #endregion Get Microsoft Entra ID account

    #region Send results to HelloID
    $microsoftEntraIDSecurityGroups | ForEach-Object {
        # Shorten DisplayName to max. 100 chars
        $displayName = "Security Group - $($_.displayName)"
        $displayName = $displayName.substring(0, [System.Math]::Min(100, $displayName.Length)) 
        
        $outputContext.Permissions.Add(
            @{
                displayName    = $displayName
                identification = @{
                    Id = $_.id
                }
            }
        )
    }
    #endregion Send results to HelloID
    #endregion Security Groups
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
