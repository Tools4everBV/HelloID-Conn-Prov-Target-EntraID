#####################################################
# HelloID-Conn-Prov-Target-ActiveDirectory-DynamicPermissions-Groups
#
# Version: 1.1.2
#####################################################
#region Initialize default properties
$c = ConvertFrom-Json $configuration
$p = $person | ConvertFrom-Json
$pp = $previousPerson | ConvertFrom-Json
$pd = $personDifferences | ConvertFrom-Json
$m = $manager | ConvertFrom-Json
$success = $false
$auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

# Operation is a script parameter which contains the action HelloID wants to perform for this permission
# It has one of the following values: "grant", "revoke", "update"
$o = $operation | ConvertFrom-Json

# The accountReference object contains the Identification object provided in the create account call
$aRef = $accountReference | ConvertFrom-Json
$mRef = $managerAccountReference | ConvertFrom-Json

# The permissionReference contains the Identification object provided in the retrieve permissions call
$pRef = $permissionReference | ConvertFrom-Json

# The entitlementContext contains the sub permissions (Previously the $permissionReference variable)
$eRef = $entitlementContext | ConvertFrom-Json

$currentPermissions = @{}
foreach ($permission in $eRef.CurrentPermissions) {
    $currentPermissions[$permission.Reference.Id] = $permission.DisplayName
}

# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$subPermissions = [Collections.Generic.List[PSCustomObject]]::new()

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($c.isDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Used to connect to Azure AD Graph API
$AADtenantID = $c.AADtenantID
$AADAppId = $c.AADAppId
$AADAppSecret = $c.AADAppSecret

# Troubleshooting
# $aRef = '2045e4e8-b7c0-489b-8edb-2a676b40a503'
# $dryRun = $false

#region functions
function Get-ADSanitizeGroupName {
    param(
        [parameter(Mandatory = $true)][String]$Name
    )
    $newName = $name.trim()
    # $newName = $newName -replace ' - ','_'
    $newName = $newName -replace '[`,~,!,#,$,%,^,&,*,(,),+,=,<,>,?,/,'',",,:,\,|,},{,.]', ''
    $newName = $newName -replace '\[', ''
    $newName = $newName -replace ']', ''
    # $newName = $newName -replace ' ','_'
    $newName = $newName -replace '\.\.\.\.\.', '.'
    $newName = $newName -replace '\.\.\.\.', '.'
    $newName = $newName -replace '\.\.\.', '.'
    $newName = $newName -replace '\.\.', '.'
    return $newName
}

function Remove-StringLatinCharacters {
    PARAM ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
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

#region Get Access Token
try {
    $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret
}
catch {
    # Clean up error variables
    $verboseErrorMessage = $null
    $auditErrorMessage = $null

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

    throw "Error creating Access Token. Error Message: $auditErrorMessage"
}
#endregion Get Access Token

#region Change mapping here
$desiredPermissions = @{}
if ($o -ne "revoke") {
    # Example: Contract Based Logic:
    foreach ($contract in $p.Contracts) {
        Write-Verbose ("Contract in condition: {0}" -f $contract.Context.InConditions)
        if ($contract.Context.InConditions -OR ($dryRun -eq $True)) {
            # Example: department_<departmentname>
            $groupName = "department_" + $contract.Department.DisplayName

            # Example: title_<titlename>
            # $groupName = "title_" + $contract.Title.Name

            # Sanitize group name, e.g. replace ' - ' with '_' or other sanitization actions 
            $groupName = Get-ADSanitizeGroupName -Name $groupName
            
            # Get group to use objectGuid to avoid name change issues
            $filter = "displayName+eq+'$($groupName)'"
            Write-Verbose "Querying Azure AD group that matches filter '$($filter)'"

            $baseUri = "https://graph.microsoft.com/"
            $splatWebRequest = @{
                Uri     = "$baseUri/v1.0/groups?`$filter=$($filter)"
                Headers = $headers
                Method  = 'GET'
            }
            $group = $null
            $groupResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
            $group = $groupResponse.Value
    
            if ($group.Id.count -eq 0) {
                Write-Error "No Group found that matches filter '$($filter)'"
            }
            elseif ($group.Id.count -gt 1) {
                Write-Error "Multiple Groups found that matches filter '$($filter)'. Please correct this so the groups are unique."
            }

            # Add group to desired permissions with the id as key and the displayname as value (use id to avoid issues with name changes and for uniqueness)
            $desiredPermissions["$($group.id)"] = $group.displayName
        }
    }
    
    # Example: Person Based Logic:
    # Example: location_<locationname>
    # $groupName = "location_" + $p.Location.Name

    # # Sanitize group name, e.g. replace ' - ' with '_' or other sanitization actions 
    # $groupName = Get-ADSanitizeGroupName -Name $groupName
    
    # # Get group to use objectGuid to avoid name change issues
    # $filter = "displayName+eq+'$($groupName)'"
    # Write-Verbose "Querying Azure AD group that matches filter '$($filter)'"

    # $baseUri = "https://graph.microsoft.com/"
    # $splatWebRequest = @{
    #     Uri     = "$baseUri/v1.0/groups?`$filter=$($filter)"
    #     Headers = $headers
    #     Method  = 'GET'
    # }
    # $group = $null
    # $groupResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
    # $group = $groupResponse.Value

    # if ($group.Id.count -eq 0) {
    #     Write-Error "No Group found that matches filter '$($filter)'"
    # }
    # elseif ($group.Id.count -gt 1) {
    #     Write-Error "Multiple Groups found that matches filter '$($filter)'. Please correct this so the groups are unique."
    # }

    # # Add group to desired permissions with the id as key and the displayname as value (use id to avoid issues with name changes and for uniqueness)
    # $desiredPermissions["$($group.id)"] = $group.displayName
}

Write-Warning ("Desired Permissions: {0}" -f ($desiredPermissions.Values | ConvertTo-Json))

Write-Warning ("Existing Permissions: {0}" -f ($eRef.CurrentPermissions.DisplayName | ConvertTo-Json))
#endregion Change mapping here

#region Execute
try {
    # Compare desired with current permissions and grant permissions
    foreach ($permission in $desiredPermissions.GetEnumerator()) {
        $subPermissions.Add([PSCustomObject]@{
                DisplayName = $permission.Value
                Reference   = [PSCustomObject]@{ Id = $permission.Name }
            })

        if (-Not $currentPermissions.ContainsKey($permission.Name)) {
            # Grant AzureAD Groupmembership
            try {
                Write-Verbose "Granting permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
    
                $bodyAddPermission = [PSCustomObject]@{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($aRef)"
                }
                $body = ($bodyAddPermission | ConvertTo-Json -Depth 10)
    
                $baseUri = "https://graph.microsoft.com/"
                $splatWebRequest = @{
                    Uri     = "$baseUri/v1.0/groups/$($permission.Name)/members/`$ref"
                    Headers = $headers
                    Method  = 'POST'
                    Body    = ([System.Text.Encoding]::UTF8.GetBytes($body))
                }
                
                if (-not($dryRun -eq $true)) {
                    $addPermission = Invoke-RestMethod @splatWebRequest -Verbose:$false
                    $auditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "Successfully granted permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would grant permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
                }
            }
            catch {
                # Clean up error variables
                $verboseErrorMessage = $null
                $auditErrorMessage = $null
    
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
                
                # Since the error message for adding a user that is already member is a 400 (bad request), we cannot check on a code or type
                # this may result in an incorrect check when the error messages are in any other language than english, please change this accordingly
                if ($auditErrorMessage -like "*One or more added object references already exist for the following modified properties*") {
                    $auditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "User '$($aRef)' is already a member of the group '$($permission.Value)'. Skipped grant of permission to group '$($permission.Value) ($($permission.Name))' for user '$($aRef)'"
                            IsError = $false
                        }
                    )
                }
                else {
                    $auditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "Error granting permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'. Error Message: $auditErrorMessage"
                            IsError = $True
                        })
                }
            }
        }    
    }

    # Compare current with desired permissions and revoke permissions
    $newCurrentPermissions = @{}
    foreach ($permission in $currentPermissions.GetEnumerator()) {    
        if (-Not $desiredPermissions.ContainsKey($permission.Name) -AND $permission.Name -ne "No Groups Defined") {
            # Revoke AzureAD Groupmembership
            try {
                Write-Verbose "Revoking permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
    
                $baseUri = "https://graph.microsoft.com/"
                $splatWebRequest = @{
                    Uri     = "$baseUri/v1.0/groups/$($permission.Name)/members/$($aRef)/`$ref"
                    Headers = $headers
                    Method  = 'DELETE'
                }
                Write-Warning ($splatWebRequest|Out-String)
    
                if (-not($dryRun -eq $true)) {
                    $removePermission = Invoke-RestMethod @splatWebRequest -Verbose:$false
                    $auditLogs.Add([PSCustomObject]@{
                            Action  = "RevokePermission"
                            Message = "Successfully revoked permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: Would revoke permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
                }
            }
            catch {
                # Clean up error variables
                $verboseErrorMessage = $null
                $auditErrorMessage = $null
    
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
             
                if ($auditErrorMessage -like "*Error code: Request_ResourceNotFound*" -and $auditErrorMessage -like "*$($permission.Name)*") {
                    $auditLogs.Add([PSCustomObject]@{
                            Action  = "RevokePermission"
                            Message = "Membership to group '$($permission.Value)' for user '$($aRef)' couldn't be found. User is already no longer a member or the group no longer exists. Skipped revoke of permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
                            IsError = $false
                        })
                }
                else {
                    $auditLogs.Add([PSCustomObject]@{
                            Action  = "RevokePermission"
                            Message = "Error revoking permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'. Error Message: $auditErrorMessage"
                            IsError = $True
                        })
                }
            }
        }
        else {
            $newCurrentPermissions[$permission.Name] = $permission.Value
        }
    }

    # Update current permissions
    # # Warning! This example will grant all permissions again! Only uncomment this when this is needed (e.g. force update)
    # if ($o -eq "update") {
    #     # Grant all desired permissions, ignoring current permissions
    #     foreach ($permission in $desiredPermissions.GetEnumerator()) {
    #         $subPermissions.Add([PSCustomObject]@{
    #                 DisplayName = $permission.Value
    #                 Reference   = [PSCustomObject]@{ Id = $permission.Name }
    #             })

    #         # Grant AzureAD Groupmembership
    #         try {
    #             Write-Verbose "Granting permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
        
    #             $bodyAddPermission = [PSCustomObject]@{
    #                 "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($aRef)"
    #             }
    #             $body = ($bodyAddPermission | ConvertTo-Json -Depth 10)
        
    #             $splatWebRequest = @{
    #                 Uri     = "$baseUri/v1.0/groups/$($permission.Name)/members/`$ref"
    #                 Headers = $headers
    #                 Method  = 'POST'
    #                 Body    = ([System.Text.Encoding]::UTF8.GetBytes($body))
    #             }
                    
    #             if (-not($dryRun -eq $true)) {
    #                 $addPermission = Invoke-RestMethod @splatWebRequest -Verbose:$false
    #                 $auditLogs.Add([PSCustomObject]@{
    #                         Action  = "UpdatePermission"
    #                         Message = "Successfully granted permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
    #                         IsError = $false
    #                     })
    #             }
    #             else {
    #                 Write-Warning "DryRun: Would grant permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'"
    #             }
    #         }
    #         catch {
    #             # Clean up error variables
    #             $verboseErrorMessage = $null
    #             $auditErrorMessage = $null
        
    #             $ex = $PSItem
    #             if ( $($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
    #                 $errorObject = Resolve-HTTPError -Error $ex
                
    #                 $verboseErrorMessage = $errorObject.ErrorMessage
                
    #                 $auditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $errorObject.ErrorMessage
    #             }
                
    #             # If error message empty, fall back on $ex.Exception.Message
    #             if ([String]::IsNullOrEmpty($verboseErrorMessage)) {
    #                 $verboseErrorMessage = $ex.Exception.Message
    #             }
    #             if ([String]::IsNullOrEmpty($auditErrorMessage)) {
    #                 $auditErrorMessage = $ex.Exception.Message
    #             }
                
    #             Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"
                    
    #             # Since the error message for adding a user that is already member is a 400 (bad request), we cannot check on a code or type
    #             # this may result in an incorrect check when the error messages are in any other language than english, please change this accordingly
    #             if ($auditErrorMessage -like "*One or more added object references already exist for the following modified properties*") {
    #                 $auditLogs.Add([PSCustomObject]@{
    #                         Action  = "UpdatePermission"
    #                         Message = "User '$($aRef)' is already a member of the group '$($permission.Value)'. Skipped grant of permission to group '$($permission.Value) ($($permission.Name))' for user '$($aRef)'"
    #                         IsError = $false
    #                     }
    #                 )
    #             }
    #             else {
    #                 $auditLogs.Add([PSCustomObject]@{
    #                         Action  = "UpdatePermission"
    #                         Message = "Error granting permission to Group '$($permission.Value) ($($permission.Name))' for account '$($aRef)'. Error Message: $auditErrorMessage"
    #                         IsError = $True
    #                     })
    #             }
    #         }
    #     }    
    # }
    
    # Handle case of empty defined dynamic permissions.  Without this the entitlement will error.
    if ($o -match "update|grant" -AND $subPermissions.count -eq 0) {
        $subPermissions.Add([PSCustomObject]@{
                DisplayName = "No Groups Defined"
                Reference   = [PSCustomObject]@{ Id = "No Groups Defined" }
            })
    }
}
#endregion Execute
finally { 
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($auditLogs.IsError -contains $true)) {
        $success = $true
    }

    #region Build up result
    $result = [PSCustomObject]@{
        Success        = $success
        SubPermissions = $subPermissions
        AuditLogs      = $auditLogs
    }
    Write-Output ($result | ConvertTo-Json -Depth 10)
    #endregion Build up result
}
