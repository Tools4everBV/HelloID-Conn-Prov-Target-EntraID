#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Create
# Create and update or correlate to account
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
function Convert-StringToBoolean($obj) {
    if ($obj -is [PSCustomObject]) {
        foreach ($property in $obj.PSObject.Properties) {
            $value = $property.Value
            if ($value -is [string]) {
                $lowercaseValue = $value.ToLower()
                if ($lowercaseValue -eq "true") {
                    $obj.$($property.Name) = $true
                }
                elseif ($lowercaseValue -eq "false") {
                    $obj.$($property.Name) = $false
                }
            }
            elseif ($value -is [PSCustomObject] -or $value -is [System.Collections.IDictionary]) {
                $obj.$($property.Name) = Convert-StringToBoolean $value
            }
            elseif ($value -is [System.Collections.IList]) {
                for ($i = 0; $i -lt $value.Count; $i++) {
                    $value[$i] = Convert-StringToBoolean $value[$i]
                }
                $obj.$($property.Name) = $value
            }
        }
    }
    return $obj
}

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

function New-AuthorizationHeaders {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[[String], [String]]])]
    param(
        [parameter(Mandatory)]
        [string]
        $TenantId,

        [parameter(Mandatory)]
        [string]
        $ClientId,

        [parameter(Mandatory)]
        [string]
        $ClientSecret
    )
    try {
        Write-Verbose "Creating Access Token"
        $baseUri = "https://login.microsoftonline.com/"
        $authUri = $baseUri + "$TenantId/oauth2/token"
    
        $body = @{
            grant_type    = "client_credentials"
            client_id     = "$ClientId"
            client_secret = "$ClientSecret"
            resource      = "https://graph.microsoft.com"
        }
    
        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token
    
        #Add the authorization header to the request
        Write-Verbose 'Adding Authorization headers'

        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add('Authorization', "Bearer $accesstoken")
        $headers.Add('Accept', 'application/json')
        $headers.Add('Content-Type', 'application/json')
        # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
        $headers.Add('ConsistencyLevel', 'eventual')

        Write-Output $headers  
    }
    catch {
        throw $_
    }
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.Powershell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
    }
}

function Resolve-MicrosoftGraphAPIErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        try {
            $errorObjectConverted = $ErrorObject | ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $errorObjectConverted.error_description) {
                $errorMessage = $errorObjectConverted.error_description
            }
            elseif ($null -ne $errorObjectConverted.error) {
                if ($null -ne $errorObjectConverted.error.message) {
                    $errorMessage = $errorObjectConverted.error.message
                    if ($null -ne $errorObjectConverted.error.code) { 
                        $errorMessage = $errorMessage + " Error code: $($errorObjectConverted.error.code)"
                    }
                }
                else {
                    $errorMessage = $errorObjectConverted.error
                }
            }
            else {
                $errorMessage = $ErrorObject
            }
        }
        catch {
            $errorMessage = $ErrorObject
        }

        Write-Output $errorMessage
    }
}
#endregion functions

#region account
# Define correlation
$correlationField = $actionContext.CorrelationConfiguration.accountField
$correlationValue = $actionContext.CorrelationConfiguration.accountFieldValue

$account = [PSCustomObject]$actionContext.Data
# Remove properties phoneAuthenticationMethod and emailAuthenticationMethod as they are set within seperate actions
$account = $account | Select-Object -ExcludeProperty phoneAuthenticationMethod, emailAuthenticationMethod
# Remove properties with null-values
$account.PsObject.Properties | ForEach-Object {
    # Remove properties with null-values
    if ($_.Value -eq $null) {
        $account.PsObject.Properties.Remove("$($_.Name)")
    }
}
# Convert the properties containing "TRUE" or "FALSE" to boolean
$account = Convert-StringToBoolean $account

# Define properties to query
$accountPropertiesToQuery = @("id") + $accountPropertiesToCompare | Select-Object -Unique
#endRegion account

try {
    #region Create authorization headers
    $actionMessage = "creating authorization headers"

    $authorizationHeadersSplatParams = @{
        TenantId     = $actionContext.Configuration.TenantID
        ClientId     = $actionContext.Configuration.AppId
        ClientSecret = $actionContext.Configuration.AppSecret
    }

    $headers = New-AuthorizationHeaders @authorizationHeadersSplatParams

    Write-Verbose "Created authorization headers. Result: $($headers | ConvertTo-Json)"
    #endregion Create authorization headers

    #region Verify correlation configuration and properties
    $actionMessage = "verifying correlation configuration and properties"

    if ($actionContext.CorrelationConfiguration.Enabled -eq $true) {
        if ([string]::IsNullOrEmpty($correlationField)) {
            throw "Correlation is enabled but not configured correctly."
        }
    
        if ([string]::IsNullOrEmpty($correlationValue)) {
            throw "The correlation value for [$correlationField] is empty. This is likely a mapping issue."
        }

        #region Get Microsoft Entra ID account
        # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http
        $actionMessage = "querying Microsoft Entra ID account where [$($correlationField)] = [$($correlationValue)]"

        $baseUri = "https://graph.microsoft.com/"
        $getMicrosoftEntraIDAccountSplatParams = @{
            Uri         = "$($baseUri)/v1.0/users?`$filter=$correlationField eq '$correlationValue'&`$select=$($accountPropertiesToQuery -join ',')"
            Headers     = $headers
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }
        $currentMicrosoftEntraIDAccount = $null
        $currentMicrosoftEntraIDAccount = (Invoke-RestMethod @getMicrosoftEntraIDAccountSplatParams).Value

        Write-Verbose "Queried Microsoft Entra ID account where [$($correlationField)] = [$($correlationValue)]. Result: $($currentMicrosoftEntraIDAccount | ConvertTo-Json)"
        #endregion Get Microsoft Entra ID account
    }
    else {
        if ($actionContext.Configuration.correlateOnly -eq $true) {
            throw "Correlation is disabled while configuration option [correlateOnly] is toggled."
        }
        else {
            Write-Verbose "Correlation is disabled."
        }
    }
    #endregion Verify correlation configuration and properties

    #region Account
    #region Calulate action
    $actionMessage = "calculating action"
    if (($currentMicrosoftEntraIDAccount | Measure-Object).count -eq 0) {
        if ($actionContext.Configuration.correlateOnly -eq $true) {
            $actionAccount = "NotFound"
        }
        else {
            $actionAccount = "Create"
        }
    }
    elseif (($currentMicrosoftEntraIDAccount | Measure-Object).count -eq 1) {
        $actionAccount = "Correlate"
    }
    elseif (($currentMicrosoftEntraIDAccount | Measure-Object).count -gt 1) {
        $actionAccount = "MultipleFound"
    }
    #endregion Calulate action

    #region Process
    switch ($actionAccount) {
        "Create" {
            #region Create account
            # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/user-post-users?view=graph-rest-1.0&tabs=http
            $actionMessage = "creating account with displayName [$($createAccountBody.displayName)] and userPrincipalName [$($createAccountBody.userPrincipalName)]"
            $baseUri = "https://graph.microsoft.com/"

            # Create account with only required fields
            $requiredFields = @("accountEnabled", "displayName", "mailNickname", "passwordProfile", "userPrincipalName")
            $createAccountBody = @{}
            foreach ($accountProperty in $account.PsObject.Properties | Where-Object { $null -ne $_.Value -and $_.Name -in $requiredFields }) {
                [void]$createAccountBody.Add($accountProperty.Name, $accountProperty.Value)
            }

            $createAccountSplatParams = @{
                Uri         = "$($baseUri)/v1.0/users"
                Headers     = $headers
                Method      = "POST"
                Body        = ($createAccountBody | ConvertTo-Json -Depth 10)
                Verbose     = $false
                ErrorAction = "Stop"
            }

            if (-Not($actionContext.DryRun -eq $true)) {
                Write-Verbose "SplatParams: $($createAccountSplatParams | ConvertTo-Json)"

                $createdAccount = Invoke-RestMethod @createAccountSplatParams

                #region Set AccountReference and add AccountReference to Data
                $outputContext.AccountReference = "$($createdAccount.id)"
                $outputContext.Data.id = "$($createdAccount.id)"
                #endregion Set AccountReference and add AccountReference to Data

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Created account with displayName [$($createAccountBody.displayName)] and userPrincipalName [$($createAccountBody.userPrincipalName)] with AccountReference: $($outputContext.AccountReference | ConvertTo-Json)."
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would create account with displayName [$($createAccountBody.displayName)] and userPrincipalName [$($createAccountBody.userPrincipalName)]."
            }
            #endregion Create account

            #region Update account
            # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0&tabs=http
            $actionMessage = "updating created account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json)"
            $baseUri = "https://graph.microsoft.com/"

            # Update account with all other fields than the required fields
            $updateAccountBody = @{}
            foreach ($accountProperty in $account.PsObject.Properties | Where-Object { $null -ne $_.Value -and $_.Name -notin $requiredFields }) {
                [void]$updateAccountBody.Add($accountProperty.Name, $accountProperty.Value)
            }

            $updateAccountSplatParams = @{
                Uri         = "$($baseUri)/v1.0/users/$($outputContext.AccountReference)"
                Headers     = $headers
                Method      = "PATCH"
                Body        = ($updateAccountBody | ConvertTo-Json -Depth 10)
                Verbose     = $false
                ErrorAction = "Stop"
            }

            if (-Not($actionContext.DryRun -eq $true)) {
                Write-Verbose "SplatParams: $($updateAccountSplatParams | ConvertTo-Json)"

                $updatedAccount = Invoke-RestMethod @updateAccountSplatParams

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Updated created account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json)."
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would update created account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json)."
            }
            #endregion Update account

            break
        }

        "Correlate" {
            #region Correlate account
            $actionMessage = "correlating to account on [$($correlationField)] = [$($correlationValue)]"

            $outputContext.AccountReference = "$($currentMicrosoftEntraIDAccount.id)"
            $outputContext.Data = $currentMicrosoftEntraIDAccount

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = "CorrelateAccount" # Optionally specify a different action for this audit log
                    Message = "Correlated to account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json) on [$($correlationField)] = [$($correlationValue)]."
                    IsError = $false
                })

            $outputContext.AccountCorrelated = $true
            #endregion Correlate account

            break
        }

        "MultipleFound" {
            #region Multiple accounts found
            $actionMessage = "correlating to account on [$($correlationField)] = [$($correlationValue)]"

            # Throw terminal error
            throw "Multiple accounts found where [$($correlationField)] = [$($correlationValue)]. Please correct this so the persons are unique."
            #endregion Multiple accounts found

            break
        }

        "NotFound" {
            #region No account found
            $actionMessage = "correlating to account on [$($correlationField)] = [$($correlationValue)]"
        
            # Throw terminal error
            throw "No account found where [$($correlationField)] = [$($correlationValue)] while configuration option [correlateOnly] is toggled. Possibly indicating that it could be deleted, or not correlated."
            #endregion No account found

            break
        }
    }
    #endregion Process
    #endregion Account
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

    $outputContext.AuditLogs.Add([PSCustomObject]@{
            # Action  = "" # Optional
            Message = $auditMessage
            IsError = $true
        })
}
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if ($outputContext.AuditLogs.IsError -contains $true) {
        $outputContext.Success = $false
    }
    else {
        $outputContext.Success = $true
    }

    # Check if accountreference is set, if not set, set this with default value as this must contain a value
    if ([String]::IsNullOrEmpty($outputContext.AccountReference)) {
        $outputContext.AccountReference = "Currently not available"
    }
}