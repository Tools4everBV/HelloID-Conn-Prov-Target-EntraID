#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-UniquenessCheck
# Check if fields are unique
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
        [object]
        $ErrorObject
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
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorObjectConverted = $ErrorObject | ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $errorObjectConverted.error_description) {
                $httpErrorObj.FriendlyMessage = $errorObjectConverted.error_description
            }
            elseif ($null -ne $errorObjectConverted.error) {
                if ($null -ne $errorObjectConverted.error.message) {
                    $httpErrorObj.FriendlyMessage = $errorObjectConverted.error.message
                    if ($null -ne $errorObjectConverted.error.code) { 
                        $httpErrorObj.FriendlyMessage = $httpErrorObj.FriendlyMessage + " Error code: $($errorObjectConverted.error.code)"
                    }
                }
                else {
                    $httpErrorObj.FriendlyMessage = $errorObjectConverted.error
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

function Convert-StringToBoolean($obj) {
    foreach ($property in $obj.PSObject.Properties) {
        $value = $property.Value
        if ($value -is [string]) {
            try {
                $obj.$($property.Name) = [System.Convert]::ToBoolean($value)
            }
            catch {
                # Handle cases where conversion fails
                $obj.$($property.Name) = $value
            }
        }
    }
    return $obj
}
#endregion functions

#region Fields to check
$fieldsToCheck = [PSCustomObject]@{
    "userPrincipalName" = [PSCustomObject]@{ # Value returned to HelloID in NonUniqueFields.
        accountValue   = $actionContext.Data.userPrincipalName
        keepInSyncWith = @("mail", "mailNickname") # Properties to synchronize with. If any of these properties are not unique, this property will also be treated as non-unique.
        crossCheckOn   = @("mail") # Properties to cross-check for uniqueness.
    }
    "mail" = [PSCustomObject]@{ # Value returned to HelloID in NonUniqueFields.
        accountValue   = $actionContext.Data.mail
        keepInSyncWith = @("userPrincipalName", "mailNickname") # Properties to synchronize with. If any of these properties are not unique, this property will also be treated as non-unique.
        crossCheckOn   = @("userPrincipalName") # Properties to cross-check for uniqueness.
    }
    "mailNickname" = [PSCustomObject]@{ # Value returned to HelloID in NonUniqueFields.
        accountValue   = $actionContext.Data.mailNickname
        keepInSyncWith = @("userPrincipalName", "mail") # Properties to synchronize with. If any of these properties are not unique, this property will also be treated as non-unique.
        crossCheckOn   = $null # Properties to cross-check for uniqueness.
    }
}
#endregion Fields to check

try {
    #region Create access token
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
    
    Write-Verbose "Created access token. Expires in: $($createAccessTokenResonse.expires_in | ConvertTo-Json)"
    #endregion Create access token
    
    #region Create headers
    $actionMessage = "creating headers"
    
    $headers = @{
        "Accept"          = "application/json"
        "Content-Type"    = "application/json;charset=utf-8"
        "Mwp-Api-Version" = "1.0"
    }
    
    Write-Verbose "Created headers. Result (without Authorization): $($headers | ConvertTo-Json)."

    # Add Authorization after printing splat
    $headers['Authorization'] = "Bearer $($createAccessTokenResonse.access_token)"
    #endregion Create headers

    if ($actionContext.Operation.ToLower() -ne "create") {
        #region Verify account reference
        $actionMessage = "verifying account reference"
    
        if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
            throw "The account reference could not be found"
        }
        #endregion Verify account reference
    }
    
    foreach ($fieldToCheck in $fieldsToCheck.PsObject.Properties | Where-Object { -not[String]::IsNullOrEmpty($_.Value.accountValue) }) {
        #region Get account
        # API docs: https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http
        $actionMessage = "querying account where [$($fieldToCheck.Name)] = [$($fieldToCheck.Value.accountValue)]"

        $filter = "$($fieldToCheck.Name) eq '$($fieldToCheck.Value.accountValue)'" 
        if (($fieldToCheck.Value.crossCheckOn | Measure-Object).Count -ge 1) {
            foreach ($fieldToCrossCheckOn in $fieldToCheck.Value.crossCheckOn) {
                $filter = $filter + " OR $($fieldToCrossCheckOn) eq '$($fieldToCheck.Value.accountValue)'"
            }
        }

        $getEntraIDAccountSplatParams = @{
            Uri         = "https://graph.microsoft.com/v1.0/users?`$filter=$($filter)&`$select=id,$($fieldToCheck.Name)"
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }

        Write-Verbose "SplatParams: $($getEntraIDAccountSplatParams | ConvertTo-Json)"

        # Add header after printing splat
        $getEntraIDAccountSplatParams['Headers'] = $headers

        $getEntraIDAccountResponse = $null
        $getEntraIDAccountResponse = Invoke-RestMethod @getEntraIDAccountSplatParams
        $correlatedAccount = $getEntraIDAccountResponse.Value
    
        Write-Verbose "Queried account where [$($fieldToCheck.Name)] = [$($fieldToCheck.Value.accountValue)]. Result: $($correlatedAccount | ConvertTo-Json)"
        #endregion Get account

        #region Check property uniqueness
        $actionMessage = "checking if property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] is unique"
        if (($correlatedAccount | Measure-Object).count -gt 0) {
            if ($actionContext.Operation.ToLower() -ne "create" -and $correlatedAccount.id -eq $actionContext.References.Account) {
                Write-Verbose "Person is using property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] themselves."
            }
            else {
                Write-Verbose "Property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] is not unique. In use by account with ID: $($correlatedAccount.id)"
                [void]$outputContext.NonUniqueFields.Add($fieldToCheck.Name)
                if (($fieldToCheck.Value.keepInSyncWith | Measure-Object).Count -ge 1) {
                    foreach ($fieldToKeepInSyncWith in $fieldToCheck.Value.keepInSyncWith | Where-Object { $_ -in $actionContext.Data.PsObject.Properties.Name }) {
                        [void]$outputContext.NonUniqueFields.Add($fieldToKeepInSyncWith)
                    }
                }
            }
        }
        elseif (($correlatedAccount | Measure-Object).count -eq 0) {
            Write-Verbose "Property [$($fieldToCheck.Name)] with value [$($fieldToCheck.Value.accountValue)] is unique."
        }
        #endregion Check property uniqueness
    }

    # Set Success to true
    $outputContext.Success = $true
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

    # Set Success to false
    $outputContext.Success = $false

    Write-Warning $warningMessage

    # Required to write an error as uniqueness check doesn't show auditlog
    Write-Error $auditMessage
}
