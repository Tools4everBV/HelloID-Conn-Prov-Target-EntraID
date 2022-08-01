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

    Write-Information "Granting permission to $($pRef.Name) ($($pRef.id)) for $($aRef)"

    # Check if user is already a member of group (error 400 will occur when user is already a member)
    $baseGraphUri = "https://graph.microsoft.com/"
    $getGroupMembershipUri = $baseGraphUri + "/v1.0/users/$($aRef)/memberOf?`$filter=id eq '$($pRef.id)'&`$count=true" 
    Write-Information ($getGroupMembershipUri | Out-String)
    $isMemberOfGroup = Invoke-RestMethod -Method GET -Uri $getGroupMembershipUri -Headers $authorization -Verbose:$false

    if($null -ne $isMemberOfGroup.Value -and $isMemberOfGroup.Value.Count -ne 0){
        Write-Information "AzureAD user $($aRef) is already a member of group $($pRef.Name) ($($pRef.id))"

        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Action  = "GrantPermission"
                Message = "Successfully granted permission to Group $($pRef.Name) ($($pRef.id)) for $($aRef) (already a member)"
                IsError = $false
            }
        )
    }else{
        if (-Not($dryRun -eq $true)) {
            $baseGraphUri = "https://graph.microsoft.com/"
            $addGroupMembershipUri = $baseGraphUri + "v1.0/groups/$($pRef.id)/members" + '/$ref'
            $body = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($aRef)" } | ConvertTo-Json -Depth 10

            $response = Invoke-RestMethod -Method POST -Uri $addGroupMembershipUri -Body $body -Headers $authorization -Verbose:$false
            Write-Information "Successfully granted permission to Group $($pRef.Name) ($($pRef.id)) for $($aRef)"
        }else{
            Write-Information $addGroupMembershipUri
            Write-Information $body
        }
    
        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Action  = "GrantPermission"
                Message = "Successfully granted permission to Group $($pRef.Name) ($($pRef.id)) for $($aRef)"
                IsError = $false
            }
        )     
    }
}
catch {
    if ($_ -like "*One or more added object references already exist for the following modified properties*") {
        Write-Information "AzureAD user $($aRef) is already a member of group $($pRef.Name) ($($pRef.id))"

        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Action  = "GrantPermission"
                Message = "Successfully granted permission to Group $($pRef.Name) ($($pRef.id)) for $($aRef) (already a member)"
                IsError = $false
            }
        )
    }
    else {
        $success = $false
        $auditLogs.Add([PSCustomObject]@{
                Action  = "GrantPermission"
                Message = "Failed to grant permission to Group $($pRef.Name) ($($pRef.id)) for $($aRef)"
                IsError = $true
            }
        )

        # Log error for further analysis.  Contact Tools4ever Support to further troubleshoot
        Write-Error "Error Granting permission to Group $($pRef.Name) ($($pRef.id)). Error: $_"
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