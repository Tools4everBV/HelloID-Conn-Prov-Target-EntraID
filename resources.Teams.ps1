#####################################################
# HelloID-Conn-Prov-Target-AzureActiveDirectory-ResourceCreation-Teams
#
# Version: 1.0.0
#####################################################
#region Initialize default properties
$c = $configuration | ConvertFrom-Json
$rRef = $resourceContext | ConvertFrom-Json
$success = $false # Set to false at start, at the end, only when no error occurs it is set to true
$auditLogs = [System.Collections.Generic.List[PSCustomObject]]::new()

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

# Hardcoded Object ID of Azure AD User to set as owner of team
$ownerAADUserId = "12345678-abcd-efgh-ijkl-mnopqrstuvwxyz90"

# Troubleshooting
$dryRun = $false

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

#region Execute
# In preview only the first 10 items of the SourceData are used
try {
    foreach ($resource in $rRef.SourceData | Where-Object { -not[String]::IsNullOrEmpty($_.Name) -and -not[String]::IsNullOrEmpty($_.Code) }) {
        Write-Verbose "Checking $($resource)"
        try {
            #region Change mapping here
            # The names of security principal objects can contain all Unicode characters except the special LDAP characters defined in RFC 2253.
            # This list of special characters includes: a leading space a trailing space and any of the following characters: # , + " \ < > 
            # A team account cannot consist solely of numbers, periods (.), or spaces. Any leading periods or spaces are cropped.
            # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc776019(v=ws.10)?redirectedfrom=MSDN
            # https://www.ietf.org/rfc/rfc2253.txt
            $teamVisibility = "Private"

            # Costcenter
            $teamName = "$($resource.Name)"
            # Sanitize team name, e.g. replace ' - ' with '_' or other sanitization actions 
            $teamName = Get-ADSanitizeGroupName -Name $teamName

            $teamDescription = "$($resource.Code)"
            #endregion Change mapping here

            $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret
            
            $teamsFilter = "resourceProvisioningOptions/Any(x:x eq 'Team')"
            $filter = "description+eq+'$($teamDescription)' & $teamsFilter"
            Write-Verbose "Querying Azure AD group that matches filter '$($filter)'"

            $baseUri = "https://graph.microsoft.com/"
            $splatWebRequest = @{
                Uri     = "$baseUri/v1.0/groups?`$filter=$($filter)&`$count=true"
                Headers = $headers
                Method  = 'GET'
            }
            $currentTeam = $null
            $currentTeamResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
            $currentTeam = $currentTeamResponse.Value

            if ($null -eq $currentTeam.Id) {
                $teamExists = $false
            }
            else {
                $teamExists = $true
            }

            # If resource does not exist
            if ($teamExists -eq $False) {
                <# Resource creation preview uses a timeout of 30 seconds
                while actual run has timeout of 10 minutes #>

                $teamObject = [PSCustomObject]@{
                    "template@odata.bind" = "https://graph.microsoft.com/v1.0/teamsTemplates('standard')"
                    displayName           = $teamName
                    description           = $teamDescription
                    visibility            = $teamVisibility

                    members               = [System.Collections.ArrayList]@()
                }

                if (-not[string]::IsNullOrEmpty($ownerAADUserId)) {
                    [void]$teamObject.members.add(
                        @{
                            "@odata.type"     = "#microsoft.graph.aadUserConversationMember"
                            roles             = @(
                                "owner"
                            )
                            "user@odata.bind" = "https://graph.microsoft.com/v1.0/users('$ownerAADUserId')"
                        }
                    )
                }

                if (-Not($dryRun -eq $True)) {
                    $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret

                    $body = $teamObject | ConvertTo-Json -Depth 10
                    $baseUri = "https://graph.microsoft.com/"
                    $splatWebRequest = @{
                        Uri     = "$baseUri/v1.0/teams"
                        Headers = $headers
                        Method  = 'POST'
                        Body    = ([System.Text.Encoding]::UTF8.GetBytes($body))
                    }
                    $newTeam = $null
                    $newTeam = Invoke-RestMethod @splatWebRequest -Verbose:$false

                    $auditLogs.Add([PSCustomObject]@{
                            Message = "Created team: $($teamObject.displayName) ($($teamObject.description))"
                            Action  = "CreateResource"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: would create team $($teamName): $($teamObject | ConvertTo-Json)"
                }
            }
            else {
                if ($dryRun -eq $True) {
                    Write-Warning "Team $($teamName) already exists"
                }

                # $auditLogs.Add([PSCustomObject]@{
                #     Message = "Skipped creation of team: $($newTeam.displayName) ($($newTeam.Id))"
                #     Action  = "CreateResource"
                #     IsError = $false
                # })
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

            # Write-Warning "Failed to create team $($teamName): $($teamObject | ConvertTo-Json). Error Message: $auditErrorMessage"

            $auditLogs.Add([PSCustomObject]@{
                    Message = "Failed to create team $($teamName). Error Message: $auditErrorMessage"
                    Action  = "CreateResource"
                    IsError = $true
                })
        }
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
        Success   = $success
        AuditLogs = $auditLogs
    }
    Write-Output ($result | ConvertTo-Json -Depth 10)
    #endregion Build up result
}