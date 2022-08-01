#region Initialize default properties
$config = ConvertFrom-Json $configuration
$p = ConvertFrom-Json $person
$aRef = $accountReference | ConvertFrom-Json

# The permissionReference object contains the Identification object provided in the retrieve permissions call
$pRef = $permissionReference | ConvertFrom-Json

$success = $true
$auditLogs = [System.Collections.Generic.List[object]]::new()

# AzureAD Application Parameters #
$AADtenantID = $config.AADtenantID
$AADAppId = $config.AADAppId
$AADAppSecret = $config.AADAppSecret

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#Retrieve account information for notifications
$account = [PSCustomObject]@{
    id = $aRef
}

# Troubleshooting (Enable if needed)
# $account = [PSCustomObject]@{
#     id = '028c2b52-d7b3-4e91-9929-ec13aa556efb'
# }
# $pRef = @{
#     Id = "c72fc32f-bbbc-4ebe-858d-cf8077662efc"
#     Name = "Azure Security Group"
# }
# $dryRun = $false

try {
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
        Authorization  = "Bearer $accesstoken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
        # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
        ConsistencyLevel = "eventual";
    }

    Write-Information "Revoking permission to $($pRef.Name) ($($pRef.id)) for $($aRef)"

    # Check if user is already a member of group (error 400 will occur when user is already a member)
    $baseGraphUri = "https://graph.microsoft.com/"
    $getGroupMembershipUri = $baseGraphUri + "/v1.0/users/$($aRef)/memberOf?`$filter=id eq '$($pRef.id)'&`$count=true" 
    Write-Information ($getGroupMembershipUri | Out-String)
    $isMemberOfGroup = Invoke-RestMethod -Method GET -Uri $getGroupMembershipUri -Headers $authorization -Verbose:$false

    if($null -eq $isMemberOfGroup.Value -or $isMemberOfGroup.Value.Count -eq 0){
        Write-Information "AzureAD user $($aRef) is is already no longer a member of group $($pRef.Name) ($($pRef.id))"

        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Action  = "RevokePermission"
                Message = "Successfully revoked permission to Group $($pRef.Name) ($($pRef.id)) for $($aRef) (already no longer a member)"
                IsError = $false
            }
        )
    }else{
        if (-Not($dryRun -eq $true)) {
            $baseGraphUri = "https://graph.microsoft.com/"
            $removeGroupMembershipUri = $baseGraphUri + "v1.0/groups/$($pRef.id)/members/$($aRef)" + '/$ref'

            $response = Invoke-RestMethod -Method DELETE -Uri $removeGroupMembershipUri -Headers $authorization -Verbose:$false
            Write-Information "Successfully revoked permission to Group $($pRef.Name) ($($pRef.id)) for $($aRef)"
        }else{
            Write-Information $removeGroupMembershipUri
            Write-Information $body
        }

        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Action  = "RevokePermission"
                Message = "Successfully revoked permission to Group $($pRef.Name) ($($pRef.id)) for $($aRef)"
                IsError = $false
            }
        )      
    }
}
catch {
    if ($_ -like "*Resource '$($pRef.id)' does not exist or one of its queried reference-property objects are not present*") {
        Write-Information "AzureAD user $($aRef) is already no longer a member or AzureAD group $($pRef.Name) ($($pRef.id)) does not exist anymore"

        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Action  = "RevokePermission"
                Message = "Successfully revoked permission to Group $($pRef.Name) ($($pRef.id)) for $($aRef) (already no longer a member or group no longer exists)"
                IsError = $false
            }
        )
    }
    else {
        $success = $false
        $auditLogs.Add([PSCustomObject]@{
                Action  = "RevokePermission"
                Message = "Failed to revoke permission to Group $($pRef.Name) ($($pRef.id)) for $($aRef)"
                IsError = $true
            }
        )

        # Log error for further analysis.  Contact Tools4ever Support to further troubleshoot
        Write-Error "Error revoking Permission to Group $($pRef.Name) ($($pRef.id)). Error: $_"
    }
}


#build up result
$result = [PSCustomObject]@{
    Success          = $success
    AccountReference = $aRef
    AuditLogs        = $auditLogs
    Account          = $account
}

Write-Output $result | ConvertTo-Json -Depth 10