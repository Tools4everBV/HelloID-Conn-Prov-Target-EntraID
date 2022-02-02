# The resourceData used in this default script uses resources based on Title
$rRef = $resourceContext | ConvertFrom-Json
$success = $true

$auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

# AzureAD Application Parameters #
$config = ConvertFrom-Json $configuration

$AADtenantID = $config.AADtenantID
$AADAppId = $config.AADAppId
$AADAppSecret = $config.AADAppSecret

# $dryRun = $false
$debug = $false

$groupType = "Microsoft 365 group" # "Microsoft 365 group" or "Security group"

# Name format: Department-<department code>
$azureAdGroupNamePrefix = "Department-"
$azureAdGroupNameSuffix = ""
$azureAdGroupDescriptionPrefix = "$groupType voor afdeling "
$azureAdGroupDescriptionSuffix = ""

#region Supporting Functions
function Get-ADSanitizeGroupName
{
    param(
        [parameter(Mandatory = $true)][String]$Name
    )
    $newName = $name.trim();
    # $newName = $newName -replace ' - ','_'
    $newName = $newName -replace '[`,~,!,#,$,%,^,&,*,(,),+,=,<,>,?,/,'',",;,:,\,|,},{,.]',''
    $newName = $newName -replace '\[','';
    $newName = $newName -replace ']','';
    # $newName = $newName -replace ' ','_';
    $newName = $newName -replace '\.\.\.\.\.','.';
    $newName = $newName -replace '\.\.\.\.','.';
    $newName = $newName -replace '\.\.\.','.';
    $newName = $newName -replace '\.\.','.';
    return $newName;
}

function Remove-StringLatinCharacters
{
    PARAM ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
}
#endregion Supporting Functions

# In preview only the first 10 items of the SourceData are used
foreach ($resource in $rRef.SourceData) {
    # Write-Information "Checking $($resource)"
    try {
        # The names of security principal objects can contain all Unicode characters except the special LDAP characters defined in RFC 2253.
        # This list of special characters includes: a leading space; a trailing space; and any of the following characters: # , + " \ < > ;
        # A group account cannot consist solely of numbers, periods (.), or spaces. Any leading periods or spaces are cropped.
        # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc776019(v=ws.10)?redirectedfrom=MSDN
        # https://www.ietf.org/rfc/rfc2253.txt
        $azureADGroupName = ("$azureADGroupNamePrefix" + "$($resource.ExternalId)" + "$azureADGroupNameSuffix")
        $azureADGroupName = Get-ADSanitizeGroupName -Name $azureADGroupName

        $azureADGroupDescription = ("$azureADGroupDescriptionPrefix" + "$($resource.name)" + "$azureADGroupDescriptionSuffix")
        
        $azureADGroupParams = @{
            displayName     = $azureADGroupName
            mailNickname    = $azureADGroupName
            groupType       = $groupType # "Microsoft 365 group" or "Security group"
            visibility      = "Public"
            description     = $azureADGroupDescription
        }

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
        }

        $baseSearchUri = "https://graph.microsoft.com/"
        $searchUri = $baseSearchUri + 'v1.0/groups?$filter=displayName+eq+' + "'$($azureADGroupParams.displayName)'"

        $azureADGroupResponse = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
        $azureADGroup = $azureADGroupResponse.value    

        if ($azureADGroup.Id.count -ge 1) {
            $groupExists = $true
        }else{
            $groupExists = $false
        }

        # If resource does not exist
        if ($groupExists -eq $False) {
            <# Resource creation preview uses a timeout of 30 seconds
            while actual run has timeout of 10 minutes #>
            Write-Information "Creating $($azureADGroupParams.displayName)"

            if (-Not($dryRun -eq $True)) {
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
                }

                $baseCreateUri = "https://graph.microsoft.com/"
                $createUri = $baseCreateUri + "v1.0/groups"

                Switch($azureADGroupParams.groupType){
                    'Microsoft 365 group' {
                        $group = [PSCustomObject]@{
                            description = $azureADGroupParams.description;
                            displayName = $azureADGroupParams.displayName;

                            groupTypes = @("Unified");

                            mailEnabled = $true;
                            mailNickname = $azureADGroupParams.mailNickname.Replace(" ","");
                            # allowExternalSenders = $allowExternalSenders; - Not supported with Application permissions
                            # autoSubscribeNewMembers = $autoSubscribeNewMembers; - Not supported with Application permissions

                            securityEnabled = $false;

                            visibility = $azureADGroupParams.visibility;
                        }
                    }

                    'Security group' {
                        $group = [PSCustomObject]@{
                            description = $azureADGroupParams.description;
                            displayName = $azureADGroupParams.displayName;

                            #groupTypes = @(""); - Needs to be empty to create Security group

                            mailEnabled = $false;
                            mailNickname = $azureADGroupParams.mailNickname.Replace(" ","");
                            # allowExternalSenders = $allowExternalSenders; - Not supported with Application permissions
                            # autoSubscribeNewMembers = $autoSubscribeNewMembers; - Not supported with Application permissions

                            securityEnabled = $true;

                            visibility = $azureADGroupParams.visibility;
                        }
                    }
                }
                $body = $group | ConvertTo-Json -Depth 10
            
                $response = Invoke-RestMethod -Uri $createUri -Method POST -Headers $authorization -Body $body -Verbose:$false
                $success = $True
                $auditLogs.Add([PSCustomObject]@{
                        Message = "Created resource for $($resource.displayName) - $($response.displayName) ($($response.Id))"
                        Action  = "CreateResource"
                        IsError = $false
                    })
            }
        }
        else {
            if ($debug -eq $true) { Write-Warning "Group $($azureADGroupParams.displayName) already exists" }
            $success = $True
            # $auditLogs.Add([PSCustomObject]@{
            #     Message = "Skipped resource for $($resource.displayName) - $($azureADGroupParams.displayName)"
            #     Action  = "CreateResource"
            #     IsError = $false
            # })
        }
        
    }
    catch {
        Write-Warning "Failed to Create $($distinguishedName). Error: $_"

        # $success = $false
        $auditLogs.Add([PSCustomObject]@{
                Message = "Failed to create resource for $($resource.name) - $distinguishedName. Error: $_"
                Action  = "CreateResource"
                IsError = $true
            })
    }
}

# Send results
$result = [PSCustomObject]@{
    Success   = $success
    AuditLogs = $auditLogs
}

Write-Output $result | ConvertTo-Json -Depth 10