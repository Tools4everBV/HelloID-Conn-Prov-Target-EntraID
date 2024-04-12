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
$correlationField = "id"
$correlationValue = $actionContext.References.Account
#endregion account

try {
    #region Verify account reference
    $actionMessage = "verifying account reference"
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw "The account reference could not be found"
    }
    #endregion Verify account reference

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

    #region Revoke permisison
    #region Calulate action
    $actionMessage = "calculating action"
    if (($currentMicrosoftEntraIDAccount | Measure-Object).count -eq 1) {
        $actionPermission = "RevokePermission"         
    }
    elseif (($currentMicrosoftEntraIDAccount | Measure-Object).count -gt 1) {
        $actionPermission = "MultipleFound"
    }
    elseif (($currentMicrosoftEntraIDAccount | Measure-Object).count -eq 0) {
        $actionPermission = "NotFound"
    }
    #endregion Calulate action

    #region Process
    switch ($actionPermission) {
        "RevokePermission" {
            #region Revoke permission from account
            # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/user-assignlicense?view=graph-rest-1.0&tabs=http
            $actionMessage = "revoking license [$($actionContext.References.Permission.SkuPartNumber)] with skuid [$($actionContext.References.Permission.SkuId)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

            $revokePermissionBody = @{
                addLicenses    = $null
                removeLicenses = @{
                    skuId = $($actionContext.References.Permission.SkuId)
                }
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
                        Message = "Revoked license [$($actionContext.References.Permission.SkuPartNumber)] with skuid [$($actionContext.References.Permission.SkuId)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would revoke license [$($actionContext.References.Permission.SkuPartNumber)] with skuid [$($actionContext.References.Permission.SkuId)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
            }
            #endregion Revoke permission from account

            break
        }

        "MultipleFound" {
            #region Multiple accounts found
            $actionMessage = "revoking license [$($actionContext.References.Permission.SkuPartNumber)] with skuid [$($actionContext.References.Permission.SkuId)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

            # Throw terminal error
            throw "Multiple accounts found where [$($correlationField)] = [$($correlationValue)]. Please correct this so the persons are unique."
            #endregion Multiple accounts found

            break
        }

        "NotFound" {
            #region No account found
            $actionMessage = "skipping revoking license [$($actionContext.References.Permission.SkuPartNumber)] with skuid [$($actionContext.References.Permission.SkuId)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"
        
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Skipped revoking license [$($actionContext.References.Permission.SkuPartNumber)] with skuid [$($actionContext.References.Permission.SkuId)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: No account found where [$($correlationField)] = [$($correlationValue)]. Possibly indicating that it could be deleted, or not correlated."
                    IsError = $false
                })
            #endregion No account found

            break
        }
    }
    #endregion Process
    #endregion Revoke permisison
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
                Message = "Skipped revoking license [$($actionContext.References.Permission.SkuPartNumber)] with skuid [$($actionContext.References.Permission.SkuId)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: User does not have the corresponding license."
                IsError = $false
            })
    }
    # Since the error message for removing a license that does not exist for the company is a 400 (bad request), we cannot check on a code or type
    # this may result in an incorrect check when the error messages are in any other language than english, please change this accordingly
    elseif ($auditMessage -like "*License $($pRef.skuId) does not correspond to a valid company License*") {
        $auditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = "Skipped revoking license [$($actionContext.References.Permission.SkuPartNumber)] with skuid [$($actionContext.References.Permission.SkuId)] from account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: License does not correspond to a valid company license."
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