#####################################################
# HelloID-Conn-Prov-Target-Azure-Permissions-RevokePermission-Group
#
# Version: 1.1.0
#####################################################
# Initialize default values
$c = $configuration | ConvertFrom-Json
$p = $person | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json

# The permissionReference object contains the Identification object provided in the retrieve permissions call
$pRef = $permissionReference | ConvertFrom-Json
$success = $true # Set to true at start, because only when an error occurs it is set to false
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($c.isDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}

# Used to connect to Azure AD Graph API
$AADtenantID = $c.AADtenantID
$AADAppId = $c.AADAppId
$AADAppSecret = $c.AADAppSecret

# Troubleshooting
$aRef = "9f4b2474-3c8d-4f92-94bc-58fed6e2d09b"
$dryRun = $false

#region functions
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

        Write-Output $headers  
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
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
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
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

# Get current Azure AD account
try {
    if ($null -eq $aRef) {
        throw "No Account Reference found in HelloID"
    }

    $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret

    Write-Verbose "Querying Azure AD account with id $($aRef)"
    $baseUri = "https://graph.microsoft.com/"
    $splatWebRequest = @{
        Uri     = "$baseUri/v1.0/users/$($aRef)"
        Headers = $headers
        Method  = 'GET'
    }
    $currentAccount = $null
    $currentAccount = Invoke-RestMethod @splatWebRequest -Verbose:$false

    if ($null -eq $currentAccount.id) {
        throw "No User found in Azure AD with id $($aRef)"
    }
}
catch {
    $ex = $PSItem
    if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObject = Resolve-HTTPError -Error $ex

        $verboseErrorMessage = $errorObject.ErrorMessage

        $auditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $errorObject.ErrorMessage
    }

    # If error message empty, fall back on $ex.Exception.Message
    if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
        $verboseErrorMessage = $ex.Exception.Message
    }
    if ([String]::IsNullOrEmpty($auditErrorMessage)) {
        $auditErrorMessage = $ex.Exception.Message
    }

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

    if ($auditErrorMessage -Like "No User found in Azure AD with id $($aRef)" -or $auditErrorMessage -Like "*(404) Not Found.*") {
        if (-Not($dryRun -eq $True)) {
            $auditLogs.Add([PSCustomObject]@{
                    Action  = "RevokePermission"
                    Message = "No Azure AD account found with id $($aRef). Possibly already deleted, skipping action."
                    IsError = $false
                })
        }
        else {
            Write-Warning "DryRun: No Azure AD account found with id $($aRef). Possibly already deleted, skipping action."
        }        
    }
    else {
        $success = $false  
        $auditLogs.Add([PSCustomObject]@{
                Action  = "RevokePermission"
                Message = "Error querying Azure AD account with id $($aRef). Error Message: $auditErrorMessage"
                IsError = $True
            })
    }
}

# Revoke permission Azure AD group for Azure AD account
if ($null -ne $currentAccount.id) {
    try {
        Write-Verbose "Revoking permission to Group '$($pRef.Name) ($($pRef.id))' for account '$($currentAccount.userPrincipalName) ($($currentAccount.id))'"

        $splatWebRequest = @{
            Uri     = "$baseUri/v1.0/groups/$($pRef.id)/members/$($aRef)/`$ref"
            Headers = $headers
            Method  = 'DELETE'
        }

        if (-not($dryRun -eq $true)) {
            $removePermission = Invoke-RestMethod @splatWebRequest -Verbose:$false
            $auditLogs.Add([PSCustomObject]@{
                    Action  = "RevokePermission"
                    Message = "Successfully revoked permission to Group '$($pRef.Name) ($($pRef.id))' for account '$($currentAccount.userPrincipalName) ($($currentAccount.id))'"
                    IsError = $false
                })
        }
        else {
            Write-Warning "DryRun: Would revoke permission to Group '$($pRef.Name) ($($pRef.id))' for account '$($currentAccount.userPrincipalName) ($($currentAccount.id))'"
        }
    }
    catch {
        $ex = $PSItem
        if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $errorObject = Resolve-HTTPError -Error $ex
    
            $verboseErrorMessage = $errorObject.ErrorMessage
    
            $auditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $errorObject.ErrorMessage
        }
    
        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
            $verboseErrorMessage = $ex.Exception.Message
        }
        if ([String]::IsNullOrEmpty($auditErrorMessage)) {
            $auditErrorMessage = $ex.Exception.Message
        }
    
        Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
        
        if ($auditErrorMessage -Like "*Resource '$($pRef.id)' does not exist or one of its queried reference-property objects are not present*") {
            $auditLogs.Add([PSCustomObject]@{
                    Action  = "RevokePermission"
                    Message = "Successfully revoked permission to Group '$($pRef.Name) ($($pRef.id))' for account '$($currentAccount.userPrincipalName) ($($currentAccount.id))' (already no longer a member or group no longer exists)"
                    IsError = $false
                }) 
        }
        else {
            $success = $false  
            $auditLogs.Add([PSCustomObject]@{
                    Action  = "RevokePermission"
                    Message = "Error revoking permission to Group '$($pRef.Name) ($($pRef.id))' for account '$($currentAccount.userPrincipalName) ($($currentAccount.id))'. Error Message: $auditErrorMessage"
                    IsError = $True
                })
        }
    }
}

# Send results
$result = [PSCustomObject]@{
    Success   = $success
    AuditLogs = $auditLogs
    Account   = $account
}
Write-Output $result | ConvertTo-Json -Depth 10