#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Delete
# Delete account
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Set debug logging
switch ($actionContext.Configuration.isDebug) {
    $true { $VerbosePreference = "Continue" }
    $false { $VerbosePreference = "SilentlyContinue" }
}
$InformationPreference = "Continue"
$WarningPreference = "Continue"

#region functions
function Resolve-MicrosoftGraphAPIError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object] $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }

        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception -is [System.Net.WebException] -and $ErrorObject.Exception.Response) {
            $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
            if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                $httpErrorObj.ErrorDetails = $streamReaderResponse
            }
        }

        try {
            $errorObjectConverted = $httpErrorObj.ErrorDetails | ConvertFrom-Json -ErrorAction Stop

            if ($errorObjectConverted.error_description) {
                $httpErrorObj.FriendlyMessage = $errorObjectConverted.error_description
            }
            elseif ($errorObjectConverted.error) {
                $httpErrorObj.FriendlyMessage = $errorObjectConverted.error.message
                if ($errorObjectConverted.error.code) {
                    $httpErrorObj.FriendlyMessage += " Error code: $($errorObjectConverted.error.code)."
                }
                if ($errorObjectConverted.error.details) {
                    if ($errorObjectConverted.error.details.message) {
                        $httpErrorObj.FriendlyMessage += " Details message: $($errorObjectConverted.error.details.message)"
                    }
                    if ($errorObjectConverted.error.details.code) {
                        $httpErrorObj.FriendlyMessage += " Details code: $($errorObjectConverted.error.details.code)."
                    }
                }
            }
            else {
                $httpErrorObj.FriendlyMessage = $ErrorObject
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }

        Write-Output $httpErrorObj
    }
}

function Convert-StringToBoolean($obj) {
    foreach ($property in $obj.PSObject.Properties) {
        $value = $property.Value
        if ($value -is [string]) {
            try {
                $obj.$($property.Name) = [System.Convert]::ToBoolean($value)
            }
            catch {
                # Handle cases where conversion fails
                $obj.$($property.Name) = $value
            }
        }
    }
    return $obj
}

function ConvertTo-FlatObject {
    param (
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Object,
        [string] $Prefix = ""
    )
    $result = [ordered]@{}

    foreach ($property in $Object.PSObject.Properties) {
        $name = if ($Prefix) { "$Prefix`.$($property.Name)" } else { $property.Name }

        if ($property.Value -is [pscustomobject]) {
            $flattenedSubObject = ConvertTo-FlatObject -Object $property.Value -Prefix $name
            foreach ($subProperty in $flattenedSubObject.PSObject.Properties) {
                $result[$subProperty.Name] = [string]$subProperty.Value
            }
        }
        else {
            $result[$name] = [string]$property.Value
        }
    }
    Write-Output ([PSCustomObject]$result)
}
#endregion functions

try {
    #region account
    # Define account object
    $account = [PSCustomObject]$actionContext.Data.PsObject.Copy()

    # Define properties to query
    $accountPropertiesToQuery = @("id") + $outputContext.Data.PsObject.Properties.Name | Select-Object -Unique

    # Remove properties of account object with null-values
    $account.PsObject.Properties | ForEach-Object {
        # Remove properties with null-values
        if ($_.Value -eq $null) {
            $account.PsObject.Properties.Remove("$($_.Name)")
        }
    }
    # Convert the properties of account object containing "TRUE" or "FALSE" to boolean
    $account = Convert-StringToBoolean $account

    # Define properties to compare for update
    $accountPropertiesToCompare = ConvertTo-FlatObject -Object $account | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name
    #endRegion account

    #region Verify account reference
    $actionMessage = "verifying account reference"
    
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw "The account reference could not be found"
    }
    #endregion Verify account reference
    
    #region Create access token
    $actionMessage = "creating access token"
    
    $createAccessTokenBody = @{
        grant_type    = "client_credentials"
        client_id     = $actionContext.Configuration.AppId
        client_secret = $actionContext.Configuration.AppSecret
        resource      = "https://graph.microsoft.com"
    }
    
    $createAccessTokenSplatParams = @{
        Uri         = "https://login.microsoftonline.com/$($actionContext.Configuration.TenantID)/oauth2/token"
        Headers     = $headers
        Body        = $createAccessTokenBody
        Method      = "POST"
        ContentType = "application/x-www-form-urlencoded"
        Verbose     = $false
        ErrorAction = "Stop"
    }
    
    $createAccessTokenResonse = Invoke-RestMethod @createAccessTokenSplatParams
    
    Write-Verbose "Created access token. Expires in: $($createAccessTokenResonse.expires_in | ConvertTo-Json)"
    #endregion Create access token
    
    #region Create headers
    $actionMessage = "creating headers"
    
    $headers = @{
        "Accept"          = "application/json"
        "Content-Type"    = "application/json;charset=utf-8"
        "Mwp-Api-Version" = "1.0"
    }
    
    Write-Verbose "Created headers. Result (without Authorization): $($headers | ConvertTo-Json)."

    # Add Authorization after printing splat
    $headers['Authorization'] = "Bearer $($createAccessTokenResonse.access_token)"
    #endregion Create headers

    #region Get account
    # API docs: https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying account with ID: $($actionContext.References.Account)"

    $getEntraIDAccountSplatParams = @{
        Uri         = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)?`$select=$($accountPropertiesToQuery -join ',')"
        Method      = "GET"
        Verbose     = $false
        ErrorAction = "Stop"
    }

    Write-Verbose "SplatParams: $($getEntraIDAccountSplatParams | ConvertTo-Json)"

    # Add header after printing splat
    $getEntraIDAccountSplatParams['Headers'] = $headers

    $getEntraIDAccountResponse = $null
    $getEntraIDAccountResponse = Invoke-RestMethod @getEntraIDAccountSplatParams
    $correlatedAccount = $getEntraIDAccountResponse
        
    Write-Verbose "Queried account with ID: $($actionContext.References.Account). Result: $($correlatedAccount | ConvertTo-Json)"
    #endregion Get account

    #region Calulate action
    $actionMessage = "calculating action"
    if (($correlatedAccount | Measure-Object).count -eq 1) {
        if ($actionContext.Configuration.deleteAccount -eq $true) {
            $actionAccount = "Delete"
        }
        else {
            $actionMessage = "comparing current account to mapped properties"

            # Set Previous data (if there are no changes between PreviousData and Data, HelloID will log "update finished with no changes")
            $outputContext.PreviousData = $correlatedAccount.PsObject.Copy()
    
            # Create flat reference object from correlated account
            $accountReferenceObject = ConvertTo-FlatObject -Object $correlatedAccount
    
            # Create flat difference object from mapped properties
            $accountDifferenceObject = ConvertTo-FlatObject -Object $account
    
            $accountSplatCompareProperties = @{
                ReferenceObject  = $accountReferenceObject.PSObject.Properties | Where-Object { $_.Name -in $accountPropertiesToCompare }
                DifferenceObject = $accountDifferenceObject.PSObject.Properties | Where-Object { $_.Name -in $accountPropertiesToCompare }
            }
    
            if ($null -ne $accountSplatCompareProperties.ReferenceObject -and $null -ne $accountSplatCompareProperties.DifferenceObject) {
                $accountPropertiesChanged = Compare-Object @accountSplatCompareProperties -PassThru
                $accountOldProperties = $accountPropertiesChanged | Where-Object { $_.SideIndicator -eq "<=" }
                $accountNewProperties = $accountPropertiesChanged | Where-Object { $_.SideIndicator -eq "=>" }
            }
    
            if ($accountNewProperties) {
                # Create custom object with old and new values
                $accountChangedPropertiesObject = [PSCustomObject]@{
                    OldValues = @{}
                    NewValues = @{}
                }
    
                # Add the old properties to the custom object with old and new values
                foreach ($accountOldProperty in $accountOldProperties) {
                    $accountChangedPropertiesObject.OldValues.$($accountOldProperty.Name) = $accountOldProperty.Value
                }
    
                # Add the new properties to the custom object with old and new values
                foreach ($accountNewProperty in $accountNewProperties) {
                    $accountChangedPropertiesObject.NewValues.$($accountNewProperty.Name) = $accountNewProperty.Value
                }
    
                Write-Verbose "Changed properties: $($accountChangedPropertiesObject | ConvertTo-Json)"
    
                $actionAccount = "Update"
            }
            else {
                $actionAccount = "NoChanges"
            }            
    
            Write-Verbose "Compared current account to mapped properties. Result: $actionAccount"
        }
    }
    elseif (($correlatedAccount | Measure-Object).count -eq 0) {
        $actionAccount = "NotFound"
    }
    elseif (($correlatedAccount | Measure-Object).count -gt 1) {
        $actionAccount = "MultipleFound"
    }
    #endregion Calulate action
    
    #region Process
    switch ($actionAccount) {
        "Delete" {
            #region Delete account
            # API docs: https://learn.microsoft.com/en-us/graph/api/user-delete?view=graph-rest-1.0&tabs=http
            $actionMessage = "deleting account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

            $deleteAccountSplatParams = @{
                Uri         = "https://graph.microsoft.com/v1.0/users/$($outputContext.AccountReference)"
                Method      = "DELETE"
                ContentType = 'application/json; charset=utf-8'
                Verbose     = $false
                ErrorAction = "Stop"
            }

            Write-Verbose "SplatParams: $($deleteAccountSplatParams | ConvertTo-Json)"

            if (-Not($actionContext.DryRun -eq $true)) {
                # Add header after printing splat
                $deleteAccountSplatParams['Headers'] = $headers

                $deleteAccountResponse = Invoke-RestMethod @deleteAccountSplatParams

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Deleted account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json)."
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would delete account with AccountReference: $($outputContext.AccountReference | ConvertTo-Json)."
            }
            #endregion Delete account

            break
        }

        "Update" {
            #region Update account
            # API docs: https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0&tabs=http
            $actionMessage = "updating account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

            # Set $outputContext.Data with correlated account
            $outputContext.Data = $correlatedAccount.PsObject.Copy()
            
            # Create custom account object for update and set with updated properties
            $updateAccountBody = [PSCustomObject]@{}
            foreach ($accountProperty in $account.PsObject.Properties) {
                $flatAccountProperty = ConvertTo-FlatObject -Object ($account | Select-Object $accountProperty.Name)
                
                foreach ($flatAccountPropertyName in ($flatAccountProperty | Get-Member -MemberType 'NoteProperty').Name) {
                    if ($flatAccountPropertyName -in $accountNewProperties.Name) {
                        if ($flatAccountPropertyName -like "*.*") {
                            $parentPropertyName = ($flatAccountPropertyName -Split '\.')[0]
                            $subPropertyName = ($flatAccountPropertyName -Split '\.')[1]
                            $subPropertyValue = ($accountProperty.Value)."$subPropertyName"

                            if (-not ($parentPropertyName -in $updateAccountBody.PSObject.Properties.Name)) {
                                $updateAccountBody | Add-Member -MemberType NoteProperty -Name $parentPropertyName -Value ([PSCustomObject]@{}) -Force

                                # Update $outputContext.Data with updated field
                                $outputContext.Data | Add-Member -MemberType NoteProperty -Name $parentPropertyName -Value ([PSCustomObject]@{}) -Force
                            }
 
                            $updateAccountBody.$parentPropertyName | Add-Member -MemberType NoteProperty -Name $subPropertyName -Value $subPropertyValue -Force
                        
                            # Update $outputContext.Data with updated field
                            $outputContext.Data.$parentPropertyName | Add-Member -MemberType NoteProperty -Name $subPropertyName -Value $subPropertyValue -Force
                        }
                        else {
                            $updateAccountBody | Add-Member -MemberType NoteProperty -Name $accountProperty.Name -Value $accountProperty.Value -Force

                            # Update $outputContext.Data with updated field
                            $outputContext.Data | Add-Member -MemberType NoteProperty -Name $accountProperty.Name -Value $accountProperty.Value -Force
                        }
                    }
                }
            }
            
            # Convert the properties of custom account object for update containing "TRUE" or "FALSE" to boolean 
            $updateAccountBody = Convert-StringToBoolean $updateAccountBody

            $updateAccountSplatParams = @{
                Uri         = "https://graph.microsoft.com/v1.0/users/$($actionContext.References.Account)"
                Method      = "PATCH"
                Body        = ($updateAccountBody | ConvertTo-Json -Depth 10)
                ContentType = 'application/json; charset=utf-8'
                Verbose     = $false
                ErrorAction = "Stop"
            }

            Write-Verbose "SplatParams: $($updateAccountSplatParams | ConvertTo-Json)"

            if (-Not($actionContext.DryRun -eq $true)) {
                # Add header after printing splat
                $updateAccountSplatParams['Headers'] = $headers

                $updateAccountResponse = Invoke-RestMethod @updateAccountSplatParams

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        # Action  = "" # Optional
                        Message = "Updated account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Old values: $($accountChangedPropertiesObject.oldValues | ConvertTo-Json). New values: $($accountChangedPropertiesObject.newValues | ConvertTo-Json)."
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Would update account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Old values: $($accountChangedPropertiesObject.oldValues | ConvertTo-Json). New values: $($accountChangedPropertiesObject.newValues | ConvertTo-Json)."
            }
            #endregion Update account

            break
        }

        "NoChanges" {
            #region No changes
            $actionMessage = "skipping updating account"

            $outputContext.Data = $correlatedAccount.PsObject.Copy()

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Skipped updating account with AccountReference: $($actionContext.References.Account | ConvertTo-Json). Reason: No changes."
                    IsError = $false
                })
            #endregion No changes

            break
        }

        "NotFound" {
            #region No account found
            $actionMessage = "updating account"

            # Throw terminal error
            throw "No account found with ID: $($actionContext.References.Account)."
            #endregion No account found

            break
        }

        "MultipleFound" {
            #region Multiple accounts found
            $actionMessage = "updating account"

            # Throw terminal error
            throw "Multiple accounts found with ID: $($actionContext.References.Account). Please correct this to ensure the correlation results in a single unique account."
            #endregion Multiple accounts found

            break
        }
    }
    #endregion Process
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MicrosoftGraphAPIError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    if ($auditMessage -like "*ResourceNotFound*" -and $auditMessage -like "*Resource '$($actionContext.References.Account)' does not exist or one of its queried reference-property objects are not present*") {
        if ($actionContext.Configuration.deleteAccount -eq $true) {
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Skipped deleting account with ID: $($actionContext.References.Account). Reason: No account found with ID: $($actionContext.References.Account). Possibly indicating that it could be deleted, or not correlated."
                    IsError = $false
                })
        }
        else {
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    # Action  = "" # Optional
                    Message = "Skipped updating account with ID: $($actionContext.References.Account). Reason: No account found with ID: $($actionContext.References.Account). Possibly indicating that it could be deleted, or not correlated."
                    IsError = $false
                })
        }
    }
    else {
        Write-Warning $warningMessage

        $outputContext.AuditLogs.Add([PSCustomObject]@{
                # Action  = "" # Optional
                Message = $auditMessage
                IsError = $true
            })
    }
}
finally {
    # Check if auditLogs contains errors, if no errors are found, set success to true
    if (-NOT($outputContext.AuditLogs.IsError -contains $true)) {
        $outputContext.Success = $true
    }
}
