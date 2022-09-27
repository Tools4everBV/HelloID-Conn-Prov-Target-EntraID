#region Initialize default properties
$config = ConvertFrom-Json $configuration
$p = $person | ConvertFrom-Json
$pp = $previousPerson | ConvertFrom-Json
$pd = $personDifferences | ConvertFrom-Json
$m = $manager | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json
$mRef = $managerAccountReference | ConvertFrom-Json
$pRef = $entitlementContext | ConvertFrom-json

$success = $false
$auditLogs = [Collections.Generic.List[PSCustomObject]]::new()
$dynamicPermissions = [Collections.Generic.List[PSCustomObject]]::new()

$config = ConvertFrom-Json $configuration
# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($($config.isDebug)) {
    $true { $VerbosePreference = 'Continue' }
    $false { $VerbosePreference = 'SilentlyContinue' }
}
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# AzureAD Application Parameters #
$AADtenantID = $config.AADtenantID
$AADAppId = $config.AADAppId
$AADAppSecret = $config.AADAppSecret

# Troubleshooting
# $aRef = '2045e4e8-b7c0-489b-8edb-2a676b40a503'
# $dryRun = $false

#region Supporting Functions
function Get-ADSanitizeGroupName {
    param(
        [parameter(Mandatory = $true)][String]$Name
    )
    $newName = $name.trim()
    $newName = $newName -replace ' - ','_'
    $newName = $newName -replace '[`,~,!,#,$,%,^,&,*,(,),+,=,<,>,?,/,'',",;,:,\,|,},{,.]', ''
    $newName = $newName -replace '\[', ''
    $newName = $newName -replace ']', ''
    $newName = $newName -replace ' ','_'
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
#endregion Supporting Functions


#region Change mapping here
$desiredPermissions = @{}
foreach ($contract in $p.Contracts) {
    Write-Verbose ("Contract in condition: {0}" -f $contract.Context.InConditions)
    if (( $contract.Context.InConditions) ) {
        # Name format: Profession-<profession code>
        $name = "Profession-$($contract.Title.ExternalId)" 
        $name = Get-ADSanitizeGroupName -Name $name

        Write-Verbose -Verbose "Generating Microsoft Graph API Access Token.."
        $baseAuthUri = "https://login.microsoftonline.com/"
        $authUri = $baseAuthUri + "$AADTenantID/oauth2/token"

        $body = @{
            grant_type    = "client_credentials"
            client_id     = "$AADAppId"
            client_secret = "$AADAppSecret"
            resource      = "https://graph.microsoft.com"
        }

        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token

        #Add the authorization header to the request
        $authorization = @{
            Authorization      = "Bearer $accesstoken"
            'Content-Type'     = "application/json"
            Accept             = "application/json"
        }

        Write-Verbose "Searching for Group displayName=$($name)"
        $baseSearchUri = "https://graph.microsoft.com/"
        $searchUri = $baseSearchUri + 'v1.0/groups?$filter=displayName+eq+' + "'$($name)'"

        $azureADGroupResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
        $azureADGroup = $azureADGroupResponse.value    

        if ($azureADGroup.Id.count -eq 0) {
            Write-Error "No Group found with name: $name"
        }
        elseif ($azureADGroup.Id.count -gt 1) {
            Write-Error "Multiple Groups found with name: $name . Please correct this so the name is unique."
        }
 
        $group_DisplayName = $azureADGroup.displayName
        $group_ObjectID = $azureADGroup.id
        $desiredPermissions["$($group_DisplayName)"] = $group_ObjectID  
    }
}

Write-Information ("Desired Permissions: {0}" -f ($desiredPermissions.keys | ConvertTo-Json))
#endregion Change mapping here

#region Execute
# Operation is a script parameter which contains the action HelloID wants to perform for this permission
# It has one of the following values: "grant", "revoke", "update"
$o = $operation | ConvertFrom-Json

if ($dryRun -eq $True) {
    # Operation is empty for preview (dry run) mode, that's why we set it here.
    $o = "grant"
}

Write-Verbose ("Existing Permissions: {0}" -f $entitlementContext.CurrentPermissions)
$currentPermissions = @{}
foreach ($permission in $pRef.CurrentPermissions) {
    $currentPermissions[$permission.Reference.Id] = $permission.DisplayName
}

# Compare desired with current permissions and grant permissions
foreach ($permission in $desiredPermissions.GetEnumerator()) {
    $dynamicPermissions.Add([PSCustomObject]@{
            DisplayName = $permission.Value
            Reference   = [PSCustomObject]@{ Id = $permission.Name }
        })

    if (-Not $currentPermissions.ContainsKey($permission.Name)) {
        # Add user to group     
        if (-Not($dryRun -eq $True)) {
            try {
                Write-Verbose "Generating Microsoft Graph API Access Token.."
                $baseAuthUri = "https://login.microsoftonline.com/"
                $authUri = $baseAuthUri + "$AADTenantID/oauth2/token"

                $body = @{
                    grant_type    = "client_credentials"
                    client_id     = "$AADAppId"
                    client_secret = "$AADAppSecret"
                    resource      = "https://graph.microsoft.com"
                }

                $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
                $accessToken = $Response.access_token

                #Add the authorization header to the request
                $authorization = @{
                    Authorization  = "Bearer $accesstoken"
                    'Content-Type' = "application/json"
                    Accept         = "application/json"
                }

                Write-Information "Granting permission for [$($aRef)]"
                $baseGraphUri = "https://graph.microsoft.com/"
                $addGroupMembershipUri = $baseGraphUri + "v1.0/groups/$($permission.Value)/members" + '/$ref'
                $body = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($aRef)" } | ConvertTo-Json -Depth 10
                
                $response = Invoke-RestMethod -Method POST -Uri $addGroupMembershipUri -Body $body -Headers $authorization -Verbose:$false

                $success = $true
                $auditLogs.Add(
                    [PSCustomObject]@{
                        Action  = "GrantDynamicPermission"
                        Message = "Successfully granted permission to Group $($permission.Name) ($($permission.Value)) for $($aRef)"
                        IsError = $false
                    }
                )
            }
            catch {
                if ($_ -like "*One or more added object references already exist for the following modified properties*") {
                    Write-Information "AzureAD user [$($aRef)] is already a member of group"
    
                    $success = $true
                    $auditLogs.Add(
                        [PSCustomObject]@{
                            Action  = "GrantDynamicPermission"
                            Message = "Successfully granted permission to Group $($permission.Name) ($($permission.Value)) for $($aRef)"
                            IsError = $false
                        }
                    )                    
                }
                else {
                    $success = $false
                    $auditLogs.Add(
                        [PSCustomObject]@{
                            Action  = "GrantDynamicPermission"
                            Message = "Failed to grant permission to Group $($permission.Name) ($($permission.Value)) for $($aRef)"
                            IsError = $true
                        }
                    )
    
                    # Log error for further analysis.  Contact Tools4ever Support to further troubleshoot.
                    Write-Error "Error granting permission to Group $($permission.Name) ($($permission.Value)). Error $_"
                }
            }
        }
    }
}

# Compare current with desired permissions and revoke permissions
$newCurrentPermissions = @{}
foreach ($permission in $currentPermissions.GetEnumerator()) {
    if (-Not $desiredPermissions.ContainsKey($permission.Name)) {
        # Remove user from group
        if (-Not($dryRun -eq $True)) {
            try {
                Write-Verbose "Generating Microsoft Graph API Access Token.."
                $baseAuthUri = "https://login.microsoftonline.com/"
                $authUri = $baseAuthUri + "$AADTenantID/oauth2/token"

                $body = @{
                    grant_type    = "client_credentials"
                    client_id     = "$AADAppId"
                    client_secret = "$AADAppSecret"
                    resource      = "https://graph.microsoft.com"
                }

                $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
                $accessToken = $Response.access_token

                #Add the authorization header to the request
                $authorization = @{
                    Authorization  = "Bearer $accesstoken"
                    'Content-Type' = "application/json"
                    Accept         = "application/json"
                }

                Write-Information "Revoking permission for [$($aRef)]"
                $baseGraphUri = "https://graph.microsoft.com/"
                $removeGroupMembershipUri = $baseGraphUri + "v1.0/groups/$($permission.Value)/members/$($aRef)" + '/$ref'

                $response = Invoke-RestMethod -Method DELETE -Uri $removeGroupMembershipUri -Headers $authorization -Verbose:$false

                $success = $true
                $auditLogs.Add(
                    [PSCustomObject]@{
                        Action  = "RevokeDynamicPermission"
                        Message = "Successfully revoked permission to Group $($permission.Name) ($($permission.Value)) for $($aRef)"
                        IsError = $false
                    }
                )
            }
            catch {
                if ($_ -like "*Resource '$($azureADGroup.id)' does not exist or one of its queried reference-property objects are not present*") {
                    Write-Information "AzureAD user [$($aRef)] is already no longer a member or AzureAD group does not exist anymore"

                    $success = $true
                    $auditLogs.Add(
                        [PSCustomObject]@{
                            Action  = "RevokeDynamicPermission"
                            Message = "Successfully revoked permission to Group $($permission.Name) ($($permission.Value)) for $($aRef)"
                            IsError = $false
                        }
                    )                    
                }
                else {
                    $success = $false
                    $auditLogs.Add(
                        [PSCustomObject]@{
                            Action  = "RevokeDynamicPermission"
                            Message = "Failed to revoke permission to Group $($permission.Name) ($($permission.Value)) for $($aRef)"
                            IsError = $true
                        }
                    )

                    # Log error for further analysis.  Contact Tools4ever Support to further troubleshoot.
                    Write-Error "Error revoking permission to Group $($permission.Name) ($($permission.Value)). Error $_"
                }
            }
        }
    }
    else {
        $newCurrentPermissions[$permission.Name] = $permission.Value
    }
}

# Update current permissions
<# Updates not needed for Group Memberships.
if ($o -eq "update") {
    foreach($permission in $newCurrentPermissions.GetEnumerator()) {    
        $auditLogs.Add([PSCustomObject]@{
            Action = "UpdateDynamicPermission"
            Message = "Updated access to department share $($permission.Value)"
            IsError = $False
        })
    }
}
#>
#endregion Execute

#region Build up result
$result = [PSCustomObject]@{
    Success            = $success
    DynamicPermissions = $dynamicPermissions
    AuditLogs          = $auditLogs
}
Write-Output $result | ConvertTo-Json -Depth 10
#endregion Build up result
