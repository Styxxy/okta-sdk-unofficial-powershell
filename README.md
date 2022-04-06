# Okta Unofficial PowerShell module
This PowerShell module is a lightweight wrapper around the Okta API (https://developer.okta.com/docs/reference/api).

Tested on:
* PowerShell 5.1
* PowerShell 7+

The cmdlets are conform the [PowerShell Approved Verbs](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7.2).
The operations are prefixed with "UOkta" (= Unofficial Okta cmdlets) to not clash with potential official "Okta" PowerShell modules.

# Available cmdlets

## Connection to the API
### Connect-UOktaAccount
Set the current Okta organization connection context.

```ps1
Connect-UOktaAccount
   -OktaInstanceUri <String>
   -ApiKey <String>
   [<CommonParameters>]
```

Example:
```ps1
Connect-UOktaAccount -OktaInstanceUri "myoktainstance.oktapreview.com" -ApiKey "ABCDEFGHIJKLMN"
```

### Disconnect-UOktaAccount
Removes the current Okta organization connection context.

```ps1
Disconnect-UOktaAccount
   [<CommonParameters>]
```

Example:
```ps1
Disconnect-UOktaAccount
```

## Users
### Get-UOktaUser
Retrieves an Okta user object.

>!NOTE
> Logins with a / character can only be fetched by id due to URL issues with escaping the / character.

```ps1
Get-UOktaUser
   -Current
   [<CommonParameters>]
```
```ps1
Get-UOktaUser
   -Id <String>
   [<CommonParameters>]
```
```ps1
Get-UOktaUser
   -Login <String>
   [<CommonParameters>]
```

Example:
```ps1
# Retrieve the current user
Get-UOktaUser -Current

# Retrieve a user based on the Okta (technical) ID
Get-UOktaUser -Id "00b1abcd1fGHIJk3L0n7"

# Retrieve a user based on the Okta login name
Get-UOktaUser -Login user@example.com
```

### New-UOktaUser
Creates a new user in your Okta organization with or without credentials.
Refer to the Okta API documentation for the object structure that have to be passed as [Profile](https://developer.okta.com/docs/reference/api/users/#profile-object) or [Credentials](https://developer.okta.com/docs/reference/api/users/#credentials-object) object.

```ps1
New-UOktaUser
   -UserProfile <PSCustomObject>
   [-Crentials <PSCustomObject>]
   [-Activate]
   [<CommonParameters>]
```

### Update-UOktaUser
Updates a user's profile and/or credentials using **partial** update semantics (POST operation per [documentation](https://developer.okta.com/docs/reference/api/users/#update-user)).
Refer to the Okta API documentation for the object structure that have to be passed as [Profile](https://developer.okta.com/docs/reference/api/users/#profile-object) or [Credentials](https://developer.okta.com/docs/reference/api/users/#credentials-object) object.

Specify `"me"` as ID for updating the Current user.
```ps1
Update-UOktaUser
   -Id <String>
   [-UserProfile <PSCustomObject>]
   [-Crentials <PSCustomObject>]
   [<CommonParameters>]
```

### Update-UOktaUserLifecycle
Lifecycle operations are non-idempotent operations that initiate a state transition for a user's status. Some operations are asynchronous while others are synchronous. The user's current status limits what operations are allowed.

```ps1
Update-UOktaUserLifecycle
   -Id <String>
   -Activate
   [-SendEmail]
   [<CommonParameters>]
```
```ps1
Update-UOktaUserLifecycle
   -Id <String>
   -Deactivate
   [-SendEmail]
   [<CommonParameters>]
```
```ps1
Update-UOktaUserLifecycle
   -Id <String>
   -Reactivate
   [-SendEmail]
   [<CommonParameters>]
```
```ps1
Update-UOktaUserLifecycle
   -Id <String>
   -Suspend
   [<CommonParameters>]
```
```ps1
Update-UOktaUserLifecycle
   -Id <String>
   -Unsuspend
   [<CommonParameters>]
```

### Get-UOktaUserGroups
Fetches the groups of which the user is a member.

Specify the user's id, login, or login shortname (as long as it is unambiguous) of the user as the `Id` parameter.

```ps1
Get-UOktaUserGroups
   -Id <String>
   [<CommonParameters>]
```

## Groups
### Get-UOktaGroups
Enumerates Groups in your organization. Currently pagination is **not** supported in this cmdlet.

```ps1
Get-UOktaGroups
   [-Limit <Int>]
   [<CommonParameters>]
```

### Get-UOktaGroupMembers
Enumerates all users that are a member of a Group. Currently pagination is **not** supported in this cmdlet.

```ps1
Get-UOktaGroupMembers
   -GroupId <String>
   [-Limit <Int>]
   [<CommonParameters>]
```

### Add-UOktaGroupMember
Adds a user to a group of `OKTA_GROUP` type.

```ps1
Add-UOktaGroupMember
   -GroupId <String>
   -UserId <String>
   [<CommonParameters>]
```

### Remove-UOktaGroupMember
Removes a user from a group of OKTA_GROUP type

```ps1
Remove-UOktaGroupMember
   -GroupId <String>
   -UserId <String>
   [<CommonParameters>]
```
