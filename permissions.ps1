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
        # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
        ConsistencyLevel = "eventual";
    }

    # Define the properties to select (comma seperated)
    # Add optinal popertySelection (mandatory: id,displayName,onPremisesSyncEnabled)
    # Comment out $properties to select all properties
    $properties = @("id", "displayName", "onPremisesSyncEnabled")
    if ($null -ne $properties) {
        $select = "&`$select=$($properties -join ",")"
    }
    else {
        $select = $null
    }

    # Currently only Microsoft 365 and Security groups are supported by the Microsoft Graph API
    # https://docs.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0
    [System.Collections.ArrayList]$groups = @()

    # Get Microsoft 365 Groups only (https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http)
    Write-Verbose -Verbose "Searching for Microsoft 365 groups.."
    $baseSearchUri = "https://graph.microsoft.com/"
    $searchUri = $baseSearchUri + "v1.0/groups?`$filter=groupTypes/any(c:c+eq+'Unified')$select" 

    $response = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    [System.Collections.ArrayList]$microsoft365Groups = $response.value
    while (![string]::IsNullOrEmpty($response.'@odata.nextLink')) {
        $response = Invoke-RestMethod -Uri $response.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
        foreach($item in $response.value){ $null = $microsoft365Groups.Add($item) }
    }
    Write-Verbose -Verbose "Finished searching for Microsoft 365 groups. Found [$($microsoft365Groups.id.Count) groups]"
    foreach($microsoft365Group in $microsoft365Groups){ $null = $groups.Add($microsoft365Group) }


    # Get Security Groups only (https://docs.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0)
    Write-Verbose -Verbose "Searching for Security groups.."
    $baseSearchUri = "https://graph.microsoft.com/"
    # Filter Cloud-Only groups (onPremisesSyncEnabled = null) and Security Groups only (https://docs.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0)
    $searchUri = $baseSearchUri + "v1.0/groups?`$filter=onPremisesSyncEnabled eq null and mailEnabled eq false and securityEnabled eq true$select"
    # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
    $searchUri = $searchUri + '&$count=true'

    $response = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    [System.Collections.ArrayList]$securityGroups = $response.value
    while (![string]::IsNullOrEmpty($response.'@odata.nextLink')) {
        $response = Invoke-RestMethod -Uri $response.'@odata.nextLink' -Method Get -Headers $authorization -Verbose:$false
        foreach($item in $response.value){ $null = $securityGroups.Add($item) }
    }
    Write-Verbose -Verbose "Finished searching for Security Groups. Found [$($securityGroups.id.Count) groups]"
    foreach($securityGroup in $securityGroups){ $null = $groups.Add($securityGroup) }

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
