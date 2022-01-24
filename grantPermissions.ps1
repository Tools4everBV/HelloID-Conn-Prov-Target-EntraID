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

# Troubleshooting (Enable if needed)
# $dryRun = $false

#Retrieve account information for notifications
$account = [PSCustomObject]@{
    id = $aRef
}

# The permissionReference contains the Identification object provided in the retrieve permissions call
if (-Not($dryRun -eq $true)) {
    try {
        Write-Verbose -Verbose "Generating Microsoft Graph API Access Token.."
        $baseAuthUri = "https://login.microsoftonline.com/"
        $authUri = $baseAuthUri + "$AADTenantID/oauth2/token"

        $body = @{
            grant_type      = "client_credentials"
            client_id       = "$AADAppId"
            client_secret   = "$AADAppSecret"
            resource        = "https://graph.microsoft.com"
        }

        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token

        #Add the authorization header to the request
        $authorization = @{
            Authorization = "Bearer $accesstoken"
            'Content-Type' = "application/json"
            Accept = "application/json"
        }

        Write-Information "Granting permission to $($pRef.Name) ($($pRef.id)) for $($aRef)"

        $baseGraphUri = "https://graph.microsoft.com/"
        $addGroupMembershipUri = $baseGraphUri + "v1.0/groups/$($pRef.id)/members" + '/$ref'
        $body = @{ "@odata.id"= "https://graph.microsoft.com/v1.0/users/$($aRef)" } | ConvertTo-Json -Depth 10

        $response = Invoke-RestMethod -Method POST -Uri $addGroupMembershipUri -Body $body -Headers $authorization -Verbose:$false
        Write-Information "Successfully granted Permission to Group $($pRef.Name) ($($pRef.id)) for $($aRef)"
    } catch {
        if($_ -like "*One or more added object references already exist for the following modified properties*"){
            Write-Information "AzureAD user $($aRef) is already a member of group $($pRef.Name) ($($pRef.id))"
        }else{
            $success = $false

            # Log error for further analysis.  Contact Tools4ever Support to further troubleshoot
            Write-Error "Error Granting Permission to Group $($pRef.Name) ($($pRef.id)). Error: $_"
        }
    }
    $auditLogs.Add([PSCustomObject]@{
        Action = "GrantPermission"
        Message = "Granted membership: {0}" -f $pRef.Name
        IsError = -Not $success
    })
}

#build up result
$result = [PSCustomObject]@{
    Success= $success
    AccountReference = $aRef
    AuditLogs = $auditLogs
    Account = $account
}

Write-Output $result | ConvertTo-Json -Depth 10