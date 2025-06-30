#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-SubPermissionsImport-Groups
# Import sub permissions
# PowerShell V2
#################################################

# Configure, must be the same as the values used in retreive permissions
$permissionReference = 'dep'
$permissionDisplayName = 'Department'

# Make sure the search query returns the same scope as the 'Handle all action script'. If this is not possible with GraphApi, then filter the data after retrieving it.
# Example using department_<departmentName>=
$searchQuery = "`$filter=startswith(displayName,'department')"
# Example when using function_<functionName>_department_<departmentName>:
# $searchQuery = '$search="displayName:function_department"'

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

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
        
        # Write-Output $httpErrorObj
        return $httpErrorObj
    }
}
#endregion functions

try {
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

    # # API docs: https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying groups"
    $entraIDGroups = @()
    $uri = "https://graph.microsoft.com/v1.0/groups?$searchQuery"
    do {
        $getGroupsSplatParams = @{
            Uri         = $uri
            Headers     = $headers
            Method      = 'GET'
            ContentType = 'application/json; charset=utf-8'
            Verbose     = $false
            ErrorAction = "Stop"
        }
        $response = Invoke-RestMethod @getGroupsSplatParams
        $entraIDGroups += $response.value
        Write-Information "Successfully queried [$($entraIDGroups.count)] existing groups"
        $uri = $response.'@odata.nextLink'
    } while ($uri)

    $actionMessage = "querying group members"
    foreach ($entraIDGroup in $entraIDGroups) {  
        $entraIDGroupMembers = @()
        $uri = "https://graph.microsoft.com/v1.0/groups/$($entraIDGroup.id)/members?`$select=id"
        do {
            $getMembershipsSplatParams = @{
                Uri         = $uri
                Headers     = $headers
                Method      = 'GET'
                ContentType = 'application/json; charset=utf-8'
                Verbose     = $false
                ErrorAction = "Stop"
            }
            $response = Invoke-RestMethod @getMembershipsSplatParams
            $users = $response.value | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.user" }
            $entraIDGroupMembers += $users
            $uri = $response.'@odata.nextLink'
        } while ($uri)
        $numberOfAccounts = $(($entraIDGroupMembers | Measure-Object).Count)   

        # Make sure the displayname has a value of max 100 char
        if (-not([string]::IsNullOrEmpty($entraIDGroup.displayName))) {
            $displayname = $($entraIDGroup.displayName).substring(0, [System.Math]::Min(100, $($entraIDGroup.displayName).Length))
        }
        else {
            $displayname = $entraIDGroup.id
        }

        $permission = @{
            PermissionReference      = @{
                Reference = $permissionReference
            }       
            DisplayName              = "Permission - $permissionDisplayName"
            SubPermissionReference   = @{
                Id = $entraIDGroup.id
            }
            SubPermissionDisplayName = $displayName
        }

        # Batch permissions based on the amount of account references, 
        # to make sure the output objects are not above the limit
        $accountsBatchSize = 500
        if ($numberOfAccounts -gt 0) {
            $accountsBatchSize = 500
            $batches = 0..($numberOfAccounts - 1) | Group-Object { [math]::Floor($_ / $accountsBatchSize ) }
            foreach ($batch in $batches) {
                $permission.AccountReferences = [array]($batch.Group | ForEach-Object { @($entraIDGroupMembers[$_].id) })
                Write-Output $permission
            }
        }
    }
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
    Write-Warning $warningMessage
    Write-Error $auditMessage
}
