Function Test-ValidUri {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $Uri
    )
    Process {
        If (-not [System.Uri]::IsWellFormedUriString($Uri, [System.UriKind]::Absolute)) {
            Return $false
        } Else {
            [System.Uri] $tmp = $null;
            If (-not [System.Uri]::TryCreate($Uri, [System.UriKind]::Absolute, [ref]$tmp)) {
                Return $false
            }
            Return $tmp.Scheme -eq [System.Uri]::UriSchemeHttp -or $tmp.Scheme -eq [System.Uri]::UriSchemeHttps
        }
    }
}

Function Connect-UOktaAccount {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $OktaInstanceUri,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $ApiKey
    )
    Begin {
        $Verbose = $PSBoundParameters.Verbose
        $Debug = $PSBoundParameters.Debug
    }
    Process {
        $_oktaUri = "https://$OktaInstanceUri"

        Write-Debug "Testing if Uri $_oktaUri is valid"
        If (-not (Test-ValidUri -Uri $_oktaUri)) {
            Throw New-Object System.ArgumentException -ArgumentList "Invalid Okta instance URI", "OktaInstanceUri"
        }

        $_config = [PSCustomObject]@{
            OktaInstanceUri = $_oktaUri
            ApiKey = $ApiKey
        }
        Set-Variable -Name UOktaInstance -Scope Global -Value $_config

        Write-Debug "Try get the current user to test if the Uri and ApiKey together are valid"
        Try {
            Get-UOktaUser -Current | Out-Null
        } Catch {
            Write-Debug "Exception occured while getting current user: $_"
            Disconnect-UOktaAccount -Verbose:$Verbose -Debug:$Debug
        }
    }
}
Export-ModuleMember -Function Connect-UOktaAccount

Function Disconnect-UOktaAccount {
    [CmdletBinding()]
    Param ()
    Process {
        Write-Debug "Remove (Global) variable UOktaInstance"
        Remove-Variable -Name UOktaInstance -Scope Global
    }
}
Export-ModuleMember -Function Disconnect-UOktaAccount

Function Get-UOktaUsers {
    [CmdletBinding()]
    Param (
        #Parameter()]
        #ValidateRange(1, [int]::MaxValue)][int] $Limit = 200,

        [Parameter()]
        [Switch] $IncludeCredentials,

        [Parameter()]
        [Switch] $IncludeCredentialsLinks,

        [Parameter()]
        [Switch] $IncludeTransitioningToStatus
    )
    Begin {
        $Verbose = $PSBoundParameters.Verbose
        $Debug = $PSBoundParameters.Debug

        If ($null -eq $Global:UOktaInstance) {
            Throw "Connect to an Okta instance before calling this method"
        }

        $_RequestMethod = "GET"
        $_RequestUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/users"
        $_RequestDefaultHeaders = @{
            Accept = "application/json"
            Authorization = "SSWS $($Global:UOktaInstance.ApiKey)"
        }

        # Determine content-type
        [string[]]$_tempOktaResponseValues = @()
        If (-not $IncludeCredentials) {
            $_tempOktaResponseValues += "omitCredentials"
        }
        If (-not $IncludeCredentialsLinks) {
            $_tempOktaResponseValues += "omitCredentialsLinks"
        }
        If (-not $IncludeTransitioningToStatus) {
            $_tempOktaResponseValues += "omitTransitioningToStatus"
        }

        $_RequestContentType = "application/json"
        If ($_tempOktaResponseValues.Count -gt 0) {
            $_RequestContentType = "$_RequestContentType; okta-response=$([String]::Join(",", $_tempOktaResponseValues))"
        }

        $_tempOktaResponseValues = $null
    }
    Process {
        Write-Debug -Message "Get-UOktaUsers: calling uri $_RequestUri"
        Return Invoke-RestMethod `
            -Uri $_RequestUri `
            -Method $_RequestMethod `
            -ContentType $_RequestContentType -SkipHeaderValidation `
            -Headers $_RequestDefaultHeaders `
            -Verbose:$Verbose -Debug:$Debug
    }
    End {
        $_RequestMethod = $null
        $_RequestUri = $null
        $_RequestDefaultHeaders = $null
        $_RequestContentType = $null
    }
}
Export-ModuleMember -Function Get-UOktaUsers

Function Get-UOktaUser {
    [CmdletBinding()]
    Param (
        [Parameter()]
        [Switch] $CurrentUser,
        
        [Parameter()]
        [String] $Id,
        
        [Parameter()]
        [String] $Login
    )
    Begin {
        $Verbose = $PSBoundParameters.Verbose
        $Debug = $PSBoundParameters.Debug

        If ($null -eq $Global:UOktaInstance) {
            Throw "Connect to an Okta instance before calling this method"
        }

        $_RequestMethod = "GET"
        $_RequestUsersApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/users/`${userId}"
        $_RequestDefaultHeaders = @{
            Accept = "application/json"
            Authorization = "SSWS $($Global:UOktaInstance.ApiKey)"
        }
    }
    Process {
        If ($CurrentUser -and (-not [string]::IsNullOrWhiteSpace($Id) -or -not [string]::IsNullOrWhiteSpace($Login))) {
            Throw "Specifies either one of the CurrentUser, Id or Login parameters."
        }
        If (-not $CurrentUser -and -not [string]::IsNullOrWhiteSpace($Id) -and -not [string]::IsNullOrWhiteSpace($Login)) {
            Throw "Specifies either one of the CurrentUser, Id or Login parameters."
        }

        $uriUserId = ""
        If ($CurrentUser) {
            $uriUserId = "me"
        } ElseIf (-not [String]::IsNullOrWhiteSpace($Id)) {
            $uriUserId = [System.Web.HttpUtility]::UrlEncode($Id)          
        } ElseIf (-not [String]::IsNullOrWhiteSpace($Login)) {
            $uriUserId = [System.Web.HttpUtility]::UrlEncode($Login)
        } Else {
            Throw "Oops"
        }

        $_RequestUri = $_RequestUsersApiUri.Replace("`${userId}", $uriUserId)
        Try {
            Write-Debug -Message "Get-UOktaUser: calling uri $_RequestUri"
            Return Invoke-RestMethod `
                -Uri $_RequestUri `
                -Method $_RequestMethod `
                -ContentType "application/json" `
                -Headers $_RequestDefaultHeaders `
                -Verbose:$Verbose -Debug:$Debug
        } Catch [Microsoft.PowerShell.Commands.HttpResponseException] {
            If ($_.Exception.Response.StatusCode -ne [System.Net.HttpStatusCode]::NotFound) {
                Throw
            }

            Write-Debug "Ignoring exception (NotFound): $($_.Exception)"
            Return $null
        }
    }
}
Export-ModuleMember -Function Get-UOktaUser

Function New-UOktaUser {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [PSCustomObject]$UserProfile,

        [Parameter()]
        [PSCustomObject]$Credentials,

        [Parameter()]
        [Switch]$Activate
    )
    Begin {
        $Verbose = $PSBoundParameters.Verbose
        $Debug = $PSBoundParameters.Debug

        If ($null -eq $Global:UOktaInstance) {
            Throw "Connect to an Okta instance before calling this method"
        }

        $_RequestMethod = "POST"
        $_RequestUsersApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/users"
        $_RequestDefaultHeaders = @{
            Accept = "application/json"
            Authorization = "SSWS $($Global:UOktaInstance.ApiKey)"
        }
    }
    Process {
        $_RequestUri = $_RequestUsersApiUri
        If ($Activate) {
            $_RequestUri = "$($_RequestUri)?activate=true"
        } Else {
            $_RequestUri = "$($_RequestUri)?activate=false"
        }

        $_RequestBody = [PSCustomObject]@{
            profile = $UserProfile
        }
        If ($null -ne $Credentials) {
            $_RequestBody | Add-Member -MemberType NoteProperty -Name credentials -Value $Credentials
        }

        Write-Debug -Message "New-UOktaUser: calling uri $_RequestUri with request body $(ConvertTo-Json $_RequestBody)"
        Return Invoke-RestMethod `
            -Uri $_RequestUri `
            -Method $_RequestMethod `
            -Headers $_RequestDefaultHeaders `
            -ContentType "application/json" `
            -Body $(ConvertTo-Json $_RequestBody) `
            -Verbose:$Verbose -Debug:$Debug
    }
}
Export-ModuleMember -Function New-UOktaUser

Function Update-UOktaUser {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Id,

        [Parameter()]
        [PSCustomObject]$UserProfile,

        [Parameter()]
        [PSCustomObject]$Credentials
    )
    Begin {
        $Verbose = $PSBoundParameters.Verbose
        $Debug = $PSBoundParameters.Debug

        If ($null -eq $Global:UOktaInstance) {
            Throw "Connect to an Okta instance before calling this method"
        }

        $_RequestMethod = "POST"
        $_RequestUsersApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/users/`${userId}"
        $_RequestDefaultHeaders = @{
            Accept = "application/json"
            Authorization = "SSWS $($Global:UOktaInstance.ApiKey)"
        }
    }
    Process {
        If ($null -eq $UserProfile -and $null -eq $Credentials) {
            Throw "Either or both UserProfile and Credentials should be specified"
        }

        $_RequestUri = $_RequestUsersApiUri.Replace("`${userId}", $Id)

        $_RequestBody = [PSCustomObject]@{}
        If ($null -ne $UserProfile) {
            $_RequestBody | Add-Member -MemberType NoteProperty -Name profile -Value $UserProfile
        }
        If ($null -ne $Credentials) {
            $_RequestBody | Add-Member -MemberType NoteProperty -Name credentials -Value $Credentials
        }

        Write-Debug -Message "Update-UOktaUser: calling uri $_RequestUri with request body $(ConvertTo-Json $_RequestBody)"
        Return Invoke-RestMethod `
            -Uri $_RequestUri `
            -Method $_RequestMethod `
            -Headers $_RequestDefaultHeaders `
            -ContentType "application/json" `
            -Body $(ConvertTo-Json $_RequestBody) `
            -Verbose:$Verbose -Debug:$Debug
    }
}
Export-ModuleMember -Function Update-UOktaUser

Function Remove-UOktaUser {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Id,

        [Parameter()]
        [Switch]$SendEmail
    )
    Begin {
        $Verbose = $PSBoundParameters.Verbose
        $Debug = $PSBoundParameters.Debug

        If ($null -eq $Global:UOktaInstance) {
            Throw "Connect to an Okta instance before calling this method"
        }

        $_RequestMethod = "DELETE"
        $_RequestUsersApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/users/`${userId}"
        $_RequestDefaultHeaders = @{
            Accept = "application/json"
            Authorization = "SSWS $($Global:UOktaInstance.ApiKey)"
        }
    }
    Process {
        $_RequestUri = $_RequestUsersApiUri.Replace("`${userId}", $Id)

        Write-Debug -Message "Remove-UOktaUser: calling uri $_RequestUri"
        Return Invoke-RestMethod `
            -Uri $_RequestUri `
            -Method $_RequestMethod `
            -Headers $_RequestDefaultHeaders `
            -ContentType "application/json"`
            -Verbose:$Verbose -Debug:$Debug
    }
}
Export-ModuleMember -Function Remove-UOktaUser

Function Update-UOktaUserLifecycle {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Id,

        [Parameter()]
        [Switch]$Activate,
        [Parameter()]
        [Switch]$Reactivate,
        [Parameter()]
        [Switch]$Deactivate,
        [Parameter()]
        [Switch]$Suspend,
        [Parameter()]
        [Switch]$Unsuspend,

        [Parameter()]
        [Switch]$SendEmail
    )
    Begin {
        $Verbose = $PSBoundParameters.Verbose
        $Debug = $PSBoundParameters.Debug

        If ($null -eq $Global:UOktaInstance) {
            Throw "Connect to an Okta instance before calling any methods."
        }

        $_RequestUserLifecycleMethod = "POST"
        $_RequestUserLifecycleActivateApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/users/`${userId}/lifecycle/activate"
        $_RequestUserLifecycleReactivateApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/users/`${userId}/lifecycle/reactivate"
        $_RequestUserLifecycleDeactivateApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/users/`${userId}/lifecycle/deactivate"
        $_RequestUserLifecycleSuspendApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/users/`${userId}/lifecycle/suspend"
        $_RequestUserLifecycleUnsuspendApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/users/`${userId}/lifecycle/unsuspend"
        $_RequestDefaultHeaders = @{
            Accept = "application/json"
            Authorization = "SSWS $($Global:UOktaInstance.ApiKey)"
        }
    }
    Process {
        If ([string]::IsNullOrWhiteSpace($Id)) {
            Throw "The Id parameter is mandatory"
        }
        If (-not $Activate -and -not $Reactivate -and -not $Deactivate -and -not $Suspend -and -not $Unsuspend) {
            Throw "Specify either Activate, Reactivate, Deactivate, Suspend or Unsuspend options"
        }
        If (
            ($Activate -and ($Reactivate -or $Deactivate -or $Suspend -or $Unsuspend)) `
            -or ($Reactivate -and ($Activate -or $Deactivate -or $Suspend -or $Unsuspend)) `
            -or ($Deactivate -and ($Activate -or $Reactivate -or $Suspend -or $Unsuspend)) `
            -or ($Suspend -and ($Activate -or $Reactivate -or $Deactivate -or $Unsuspend)) `
            -or ($Unsuspend -and ($Activate -or $Reactivate -or $Deactivate -or $Suspend))
        ) {
            Throw "Only one option Activate, Reactivate, Deactivate, Suspend or Unsuspend at the same time is allowed"
        }
        If ($SendEmail -and ($Suspend -or $Unsuspend)) {
            Throw "SendEmail parameter can only be specified with Activate, Reactivate or Deactivate options"
        }

        $_RequestUri = ""
        If ($Activate) {
            $_RequestUri = $_RequestUserLifecycleActivateApiUri
        } ElseIf ($Reactivate) {
            $_RequestUri = $_RequestUserLifecycleReactivateApiUri
        } ElseIf ($Deactivate) {
            $_RequestUri = $_RequestUserLifecycleDeactivateApiUri
        } ElseIf ($Suspend) {
            $_RequestUri = $_RequestUserLifecycleSuspendApiUri
        } ElseIf ($Unsuspend) {
            $_RequestUri = $_RequestUserLifecycleUnsuspendApiUri
        } Else {
            Throw "Not configured option"
        }
        $_RequestUri = $_RequestUri.Replace("`${userId}", $Id)

        If ($Activate -or $Reactivate -or $Deactivate) {
            If ($SendEmail) {
                $_RequestUri = "$($_RequestUri)?sendEmail=true"
            } Else {
                $_RequestUri = "$($_RequestUri)?sendEmail=false"
            }
        }

        Write-Debug -Message "Update-UOktaUserLifecycle: calling uri $_RequestUri"
        Return Invoke-RestMethod `
            -Uri $_RequestUri `
            -Method $_RequestUserLifecycleMethod `
            -Headers $_RequestDefaultHeaders `
            -ContentType "application/json" `
            -Verbose:$Verbose -Debug:$Debug
    }
}
Export-ModuleMember -Function Update-UOktaUserLifecycle

Function Set-UOktaUserPasswordExpired {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Id,

        [Parameter()]
        [Switch]$TempPassword
    )
    Begin {
        $Verbose = $PSBoundParameters.Verbose
        $Debug = $PSBoundParameters.Debug

        If ($null -eq $Global:UOktaInstance) {
            Throw "Connect to an Okta instance before calling any methods."
        }

        $_RequestUserLifecycleMethod = "POST"
        $_RequestApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/users/`${userId}/lifecycle/expire_password"
        $_RequestDefaultHeaders = @{
            Accept = "application/json"
            Authorization = "SSWS $($Global:UOktaInstance.ApiKey)"
        }
    }
    Process {
        If ([string]::IsNullOrWhiteSpace($Id)) {
            Throw "The Id parameter is mandatory"
        }

        $_RequestUri = $_RequestApiUri.Replace("`${userId}", $Id)
        If ($TempPassword) {
            $_RequestUri = "$($_RequestUri)?tempPassword=true"
        }

        Write-Debug -Message "Set-UOktaUserPasswordExpired: calling uri $_RequestUri"
        Return Invoke-RestMethod `
            -Uri $_RequestUri `
            -Method $_RequestUserLifecycleMethod `
            -Headers $_RequestDefaultHeaders `
            -ContentType "application/json" `
            -Verbose:$Verbose -Debug:$Debug
    }
    End {
        $_RequestUserLifecycleMethod = $null
        $_RequestApiUri = $null
        $_RequestDefaultHeaders = $null
    }
}
Export-ModuleMember -Function Set-UOktaUserPasswordExpired

Function Remove-UOktaUserFactors {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Id
    )
    Begin {
        $_Verbose = $PSBoundParameters.Verbose
        $_Debug = $PSBoundParameters.Debug

        If ($null -eq $Global:UOktaInstance) {
            Throw "Connect to an Okta instance before calling any methods."
        }

        $_RequestUserLifecycleMethod = "POST"
        $_RequestApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/users/`${userId}/lifecycle/reset_factors"
        $_RequestDefaultHeaders = @{
            Accept = "application/json"
            Authorization = "SSWS $($Global:UOktaInstance.ApiKey)"
        }
    }
    Process {
        If ([string]::IsNullOrWhiteSpace($Id)) {
            Throw "The Id parameter is mandatory"
        }

        $_RequestUri = $_RequestApiUri.Replace("`${userId}", $Id)

        Write-Debug -Message "Remove-UOktaUserFactors: calling uri $_RequestUri"
        Return Invoke-RestMethod `
            -Uri $_RequestUri `
            -Method $_RequestUserLifecycleMethod `
            -Headers $_RequestDefaultHeaders `
            -ContentType "application/json" `
            -Verbose:$_Verbose -Debug:$_Debug
    }
    End {
        $_RequestUserLifecycleMethod = $null
        $_RequestApiUri = $null
        $_RequestDefaultHeaders = $null
        $_Verbose = $null
        $_Debug = $null
    }
}
Export-ModuleMember -Function Remove-UOktaUserFactors

Function Remove-UOktaUserSessions {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Id,

        [Parameter()]
        [Switch]$OauthTokens
    )
    Begin {
        $Verbose = $PSBoundParameters.Verbose
        $Debug = $PSBoundParameters.Debug

        If ($null -eq $Global:UOktaInstance) {
            Throw "Connect to an Okta instance before calling any methods."
        }

        $_RequestUserLifecycleMethod = "DELETE"
        $_RequestApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/users/`${userId}/sessions"
        $_RequestDefaultHeaders = @{
            Accept = "application/json"
            Authorization = "SSWS $($Global:UOktaInstance.ApiKey)"
        }
    }
    Process {
        If ([string]::IsNullOrWhiteSpace($Id)) {
            Throw "The Id parameter is mandatory"
        }

        $_RequestUri = $_RequestApiUri.Replace("`${userId}", $Id)
        If ($OauthTokens) {
            $_RequestUri = "$($_RequestUri)?oauthTokens=true"
        }

        Write-Debug -Message "Remove-UOktaUserSessions: calling uri $_RequestUri"
        Return Invoke-RestMethod `
            -Uri $_RequestUri `
            -Method $_RequestUserLifecycleMethod `
            -Headers $_RequestDefaultHeaders `
            -ContentType "application/json" `
            -Verbose:$Verbose -Debug:$Debug
    }
    End {
        $_RequestUserLifecycleMethod = $null
        $_RequestApiUri = $null
        $_RequestDefaultHeaders = $null
    }
}
Export-ModuleMember -Function Remove-UOktaUserSessions

Function Get-UOktaUserGroups {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Id
    )
    Begin {
        $Verbose = $PSBoundParameters.Verbose
        $Debug = $PSBoundParameters.Debug

        If ($null -eq $Global:UOktaInstance) {
            Throw "Connect to an Okta instance before calling any methods."
        }

        $_RequestMethod = "GET"
        $_RequestUserGroupsApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/users/`${userId}/groups"
        $_RequestDefaultHeaders = @{
            Accept = "application/json"
            Authorization = "SSWS $($Global:UOktaInstance.ApiKey)"
        }
    }
    Process {
        If ([String]::IsNullOrWhiteSpace($Id)) {
            Throw "The Id parameter is mandatory"
        }

        $_RequestUri = $_RequestUserGroupsApiUri.Replace("`${userId}", $Id)

        Try {
            Write-Debug -Message "Calling uri $_RequestUri"
            Return Invoke-RestMethod `
                -Uri $_RequestUri `
                -Method $_RequestMethod `
                -ContentType "application/json" `
                -Headers $_RequestDefaultHeaders `
                -Verbose:$Verbose -Debug:$Debug
        } Catch [Microsoft.PowerShell.Commands.HttpResponseException] {
            If ($_.Exception.Response.StatusCode -ne [System.Net.HttpStatusCode]::NotFound) {
                Throw
            }

            Write-Debug "Ignoring exception (NotFound): $($_.Exception)"
            Return @()
        }
    }
}
Export-ModuleMember -Function Get-UOktaUserGroups

Function Get-UOktaUserApplications {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Id
    )
    Begin {
        $Verbose = $PSBoundParameters.Verbose
        $Debug = $PSBoundParameters.Debug

        If ($null -eq $Global:UOktaInstance) {
            Throw "Connect to an Okta instance before calling any methods."
        }

        $_RequestMethod = "GET"
        $_RequestApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/apps?filter=user.id eq `"`${userId}`""
        $_RequestDefaultHeaders = @{
            Accept = "application/json"
            Authorization = "SSWS $($Global:UOktaInstance.ApiKey)"
        }
    }
    Process {        
        If ([String]::IsNullOrWhiteSpace($Id)) {
            Throw "The Id parameter is mandatory"
        }
        
        $_RequestUri = $_RequestApiUri.Replace("`${userId}", $Id)

        Try {
            Write-Debug -Message "Calling uri $_RequestUri"
            Return Invoke-RestMethod `
                -Uri $_RequestUri `
                -Method $_RequestMethod `
                -ContentType "application/json" `
                -Headers $_RequestDefaultHeaders `
                -Verbose:$Verbose -Debug:$Debug
        } Catch [Microsoft.PowerShell.Commands.HttpResponseException] {
            If ($_.Exception.Response.StatusCode -ne [System.Net.HttpStatusCode]::NotFound) {
                Throw
            }

            Write-Debug "Ignoring exception (NotFound): $($_.Exception)"
            Return @()
        }
    }
}
Export-ModuleMember -Function Get-UOktaUserApplications

Function Get-UOktaGroups {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [int]$Limit = 200
    )
    Begin {
        $Verbose = $PSBoundParameters.Verbose
        $Debug = $PSBoundParameters.Debug

        If ($null -eq $Global:UOktaInstance) {
            Throw "Connect to an Okta instance before calling any methods."
        }

        $_RequestMethod = "GET"
        $_RequestGroupMembersApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/groups"
        $_RequestDefaultHeaders = @{
            Accept = "application/json"
            Authorization = "SSWS $($Global:UOktaInstance.ApiKey)"
        }
    }
    Process {
        If ($Limit -le 0) {
            Throw "Limit value $Limit should be greater than 0"
        }

        $_RequestUri = "$($_RequestGroupMembersApiUri.Replace("`${groupId}", $GroupId))?limit=$Limit"

        Write-Debug -Message "Calling uri $_RequestUri"
        Return Invoke-RestMethod `
            -Uri $_RequestUri `
            -Method $_RequestMethod `
            -ContentType "application/json" `
            -Headers $_RequestDefaultHeaders `
            -Verbose:$Verbose -Debug:$Debug
    }
}
Export-ModuleMember -Function Get-UOktaGroups

Function Get-UOktaGroupMembers {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$GroupId,
        
        [Parameter(Mandatory=$false)]
        [int]$Limit = 200
    )
    Begin {
        $Verbose = $PSBoundParameters.Verbose
        $Debug = $PSBoundParameters.Debug

        If ($null -eq $Global:UOktaInstance) {
            Throw "Connect to an Okta instance before calling any methods."
        }

        $_RequestMethod = "GET"
        $_RequestGroupsApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/groups/`${groupId}/users"
        $_RequestDefaultHeaders = @{
            Accept = "application/json"
            Authorization = "SSWS $($Global:UOktaInstance.ApiKey)"
        }
    }
    Process {
        If ([String]::IsNullOrWhiteSpace($GroupId)) {
            Throw "GroupId parameter is required"
        }
        If ($Limit -le 0) {
            Throw "Limit value $Limit should be greater than 0"
        }

        $_RequestUri = "$($_RequestGroupsApiUri)?limit=$Limit"

        Write-Debug -Message "Calling uri $_RequestUri"
        Return Invoke-RestMethod `
            -Uri $_RequestUri `
            -Method $_RequestMethod `
            -ContentType "application/json" `
            -Headers $_RequestDefaultHeaders `
            -Verbose:$Verbose -Debug:$Debug
    }
}
Export-ModuleMember -Function Get-UOktaGroupMembers

Function Add-UOktaGroupMember {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$GroupId,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$UserId
    )
    Begin {
        $Verbose = $PSBoundParameters.Verbose
        $Debug = $PSBoundParameters.Debug

        If ($null -eq $Global:UOktaInstance) {
            Throw "Connect to an Okta instance before calling any methods."
        }

        $_RequestMethod = "PUT"
        $_RequestGroupMemberApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/groups/`${groupId}/users/`${userId}"
        $_RequestDefaultHeaders = @{
            Accept = "application/json"
            Authorization = "SSWS $($Global:UOktaInstance.ApiKey)"
        }
    }
    Process {
        If ([String]::IsNullOrWhiteSpace($GroupId)) {
            Throw "GroupId parameter is required"
        }
        If ([String]::IsNullOrWhiteSpace($UserId)) {
            Throw "UserId parameter is required"
        }

        $_RequestUri = $_RequestGroupMemberApiUri.Replace("`${groupId}", $GroupId).Replace("`${userId}", $UserId)

        Write-Debug -Message "Calling uri $_RequestUri"
        Return Invoke-RestMethod `
            -Uri $_RequestUri `
            -Method $_RequestMethod `
            -ContentType "application/json" `
            -Headers $_RequestDefaultHeaders `
            -Verbose:$Verbose -Debug:$Debug
    }
}
Export-ModuleMember -Function Add-UOktaGroupMember

Function Remove-UOktaGroupMember {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$GroupId,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$UserId
    )
    Begin {
        $Verbose = $PSBoundParameters.Verbose
        $Debug = $PSBoundParameters.Debug

        If ($null -eq $Global:UOktaInstance) {
            Throw "Connect to an Okta instance before calling any methods."
        }

        $_RequestMethod = "DELETE"
        $_RequestGroupMemberApiUri = "$($Global:UOktaInstance.OktaInstanceUri)/api/v1/groups/`${groupId}/users/`${userId}"
        $_RequestDefaultHeaders = @{
            Accept = "application/json"
            Authorization = "SSWS $($Global:UOktaInstance.ApiKey)"
        }
    }
    Process {
        If ([String]::IsNullOrWhiteSpace($GroupId)) {
            Throw "GroupId parameter is required"
        }
        If ([String]::IsNullOrWhiteSpace($UserId)) {
            Throw "UserId parameter is required"
        }

        $_RequestUri = $_RequestGroupMemberApiUri.Replace("`${groupId}", $GroupId).Replace("`${userId}", $UserId)

        Write-Debug -Message "Calling uri $_RequestUri"
        Return Invoke-RestMethod `
            -Uri $_RequestUri `
            -Method $_RequestMethod `
            -ContentType "application/json" `
            -Headers $_RequestDefaultHeaders `
            -Verbose:$Verbose -Debug:$Debug
    }
}
Export-ModuleMember -Function Remove-UOktaGroupMember
