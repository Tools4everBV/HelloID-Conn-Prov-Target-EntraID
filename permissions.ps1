# AzureAD Application Parameters #
$config = ConvertFrom-Json $configuration

$AADtenantID = $config.AADtenantID
$AADAppId = $config.AADAppId
$AADAppSecret = $config.AADAppSecret

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

try{
    Write-Verbose -Verbose "Generating Microsoft Graph API Access Token.."
    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
        ConsistencyLevel = "eventual";
    }

    Write-Verbose -Verbose "Searching for AzureAD groups.."

    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + 'v1.0/groups' + '?$filter=' + "onPremisesSyncEnabled eq null" + '%26$count=true'
    $searchUri = [System.Web.HttpUtility]::UrlDecode($searchUri)

    $response = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    [System.Collections.ArrayList]$groups = $response.value
    while (![string]::IsNullOrEmpty($response.'@odata.nextLink')) {
        $response = Invoke-RestMethod -Uri $response.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
        foreach($item in $response.value){
            $null = $groups.Add($item)
        }
    }    
    Write-Verbose -Verbose "Finished searching for AzureAD Groups. Found [$($groups.id.Count) groups]"    
}catch{
    throw "Could not gather Azure AD groups. Error: $_"
}

$permissions = @(foreach($group in $groups){
    @{
      displayName = $group.displayName;
        Identification = @{
            Id = $group.id;
            Name = $group.displayName;
        }
    }
})

Write-output $permissions | ConvertTo-Json -Depth 10;
