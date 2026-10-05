<#
.SYNOPSIS
    Shows the signed-in user's effective Entra memberships and Defender XDR RBAC access.

.DESCRIPTION
    This script:

    1. Signs in interactively as the user being tested.
    2. Shows the signed-in user.
    3. Retrieves transitive Entra group and directory-role memberships.
    4. Resolves GUIDs to readable group / role names.
    5. Retrieves Microsoft Defender XDR Unified RBAC role definitions.
    6. Shows Defender role names and allowed resource actions.
    7. Attempts to correlate Defender role assignments with the user's groups.
    8. Prints a readable summary.

.NOTES
    Run this script in the security context of the colleague/user whose access
    you want to verify.

    Required Microsoft Graph PowerShell module:
        Install-Module Microsoft.Graph -Scope CurrentUser

    Defender Unified RBAC currently uses the Microsoft Graph Defender
    roleManagement provider. Some properties can differ depending on API
    version / tenant configuration, therefore assignment parsing is defensive.
#>

#Requires -Version 7.0

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================================
# CONFIGURATION
# ============================================================================

$DefenderGroupPattern = '(?i)Defender|MDE|MDI|MDO|XDR|Security|SOC|Sentinel'

$Scopes = @(
    "User.Read"
    "GroupMember.Read.All"
    "RoleManagement.Read.Directory"
    "RoleManagement.Read.Defender"
)

# ============================================================================
# VARIABLES
# ============================================================================

$Me                   = $null
$Memberships          = @()
$Groups               = @()
$DirectoryRoles       = @()
$SecurityGroups       = @()
$EntraRoleDefinitions = @()

$DefenderRoleDefinitions = @()
$DefenderRoleAssignments = @()
$EffectiveAssignments     = @()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Section {

    param(
        [Parameter(Mandatory)]
        [string]$Title
    )

    Write-Host ""
    Write-Host $Title -ForegroundColor Yellow
    Write-Host ("-" * $Title.Length) -ForegroundColor DarkGray
}

function Invoke-GraphPagedRequest {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $Results = [System.Collections.Generic.List[object]]::new()
    $NextUri = $Uri

    do {

        Write-Verbose "Graph GET: $NextUri"

        $Response = Invoke-MgGraphRequest `
            -Method GET `
            -Uri $NextUri `
            -OutputType PSObject `
            -ErrorAction Stop

        # Collection response
        if ($null -ne $Response.PSObject.Properties["value"]) {

            foreach ($Item in @($Response.value)) {
                $Results.Add($Item)
            }

        }
        else {

            # Single-object response
            $Results.Add($Response)
        }

        # Pagination
        $NextLinkProperty = $Response.PSObject.Properties["@odata.nextLink"]

        if ($null -ne $NextLinkProperty) {
            $NextUri = $NextLinkProperty.Value
        }
        else {
            $NextUri = $null
        }

    } while ($NextUri)

    return $Results.ToArray()
}

function Get-SafePropertyValue {

    param(
        [Parameter(Mandatory)]
        [object]$Object,

        [Parameter(Mandatory)]
        [string]$PropertyName
    )

    $Property = $Object.PSObject.Properties[$PropertyName]

    if ($null -ne $Property) {
        return $Property.Value
    }

    return $null
}

function Resolve-DirectoryRole {

    param(
        [Parameter(Mandatory)]
        [object]$Membership,

        [Parameter(Mandatory)]
        [array]$RoleDefinitions
    )

    $RoleName        = $null
    $RoleDescription = $null
    $RoleTemplateId  = Get-SafePropertyValue `
        -Object $Membership `
        -PropertyName "roleTemplateId"

    # First try information already returned by transitiveMemberOf
    $MembershipDisplayName = Get-SafePropertyValue `
        -Object $Membership `
        -PropertyName "displayName"

    $MembershipDescription = Get-SafePropertyValue `
        -Object $Membership `
        -PropertyName "description"

    if ($MembershipDisplayName) {
        $RoleName = $MembershipDisplayName
    }

    if ($MembershipDescription) {
        $RoleDescription = $MembershipDescription
    }

    # If roleTemplateId was included, resolve against unified role definitions
    if ($RoleTemplateId) {

        $RoleDefinition = $RoleDefinitions |
            Where-Object {
                $_.templateId -eq $RoleTemplateId -or
                $_.id -eq $RoleTemplateId
            } |
            Select-Object -First 1

        if ($RoleDefinition) {

            if ($RoleDefinition.displayName) {
                $RoleName = $RoleDefinition.displayName
            }

            if ($RoleDefinition.description) {
                $RoleDescription = $RoleDefinition.description
            }
        }
    }

    # If the object was returned with limited information, explicitly query it
    if (-not $RoleName) {

        try {

            $DirectoryRole = Invoke-MgGraphRequest `
                -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($Membership.id)" `
                -OutputType PSObject `
                -ErrorAction Stop

            $DirectoryRoleName = Get-SafePropertyValue `
                -Object $DirectoryRole `
                -PropertyName "displayName"

            $DirectoryRoleDescription = Get-SafePropertyValue `
                -Object $DirectoryRole `
                -PropertyName "description"

            $DirectoryRoleTemplateId = Get-SafePropertyValue `
                -Object $DirectoryRole `
                -PropertyName "roleTemplateId"

            if ($DirectoryRoleName) {
                $RoleName = $DirectoryRoleName
            }

            if ($DirectoryRoleDescription) {
                $RoleDescription = $DirectoryRoleDescription
            }

            if ($DirectoryRoleTemplateId) {

                $RoleDefinition = $RoleDefinitions |
                    Where-Object {
                        $_.templateId -eq $DirectoryRoleTemplateId -or
                        $_.id -eq $DirectoryRoleTemplateId
                    } |
                    Select-Object -First 1

                if ($RoleDefinition) {

                    if ($RoleDefinition.displayName) {
                        $RoleName = $RoleDefinition.displayName
                    }

                    if ($RoleDefinition.description) {
                        $RoleDescription = $RoleDefinition.description
                    }
                }
            }
        }
        catch {
            # Do not abort entire script because one role cannot be resolved
        }
    }

    if (-not $RoleName) {
        $RoleName = "<Unable to resolve>"
    }

    [PSCustomObject]@{
        Type        = "Entra Directory Role"
        Name        = $RoleName
        ObjectId    = $Membership.id
        Description = $RoleDescription
    }
}

function Get-DefenderRolePermissions {

    param(
        [Parameter(Mandatory)]
        [object]$RoleDefinition
    )

    $Actions = [System.Collections.Generic.List[string]]::new()

    $RolePermissions = Get-SafePropertyValue `
        -Object $RoleDefinition `
        -PropertyName "rolePermissions"

    foreach ($PermissionSet in @($RolePermissions)) {

        if ($null -eq $PermissionSet) {
            continue
        }

        $AllowedActions = Get-SafePropertyValue `
            -Object $PermissionSet `
            -PropertyName "allowedResourceActions"

        foreach ($Action in @($AllowedActions)) {

            if ($Action) {
                $Actions.Add([string]$Action)
            }
        }
    }

    return @(
        $Actions |
            Sort-Object -Unique
    )
}

# ============================================================================
# MODULE CHECK
# ============================================================================

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {

    Write-Host ""
    Write-Host "Microsoft.Graph is not installed." -ForegroundColor Red
    Write-Host ""
    Write-Host "Install it with:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Install-Module Microsoft.Graph -Scope CurrentUser" `
        -ForegroundColor Cyan

    return
}

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# ============================================================================
# HEADER
# ============================================================================

Write-Host ""
Write-Host "============================================================" `
    -ForegroundColor DarkCyan

Write-Host " DEFENDER / ENTRA PERMISSION CHECK" `
    -ForegroundColor Cyan

Write-Host "============================================================" `
    -ForegroundColor DarkCyan

# ============================================================================
# CONNECT
# ============================================================================

try {

    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    Connect-MgGraph `
        -Scopes $Scopes `
        -ContextScope Process `
        -NoWelcome

}
catch {

    Write-Host ""
    Write-Host "Graph login failed." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red

    return
}

# ============================================================================
# CURRENT USER
# ============================================================================

try {

    $Me = Invoke-MgGraphRequest `
        -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/me?`$select=id,displayName,userPrincipalName" `
        -OutputType PSObject

}
catch {

    Write-Host ""
    Write-Host "Unable to retrieve signed-in user." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red

    return
}

Write-Section "SIGNED-IN USER"

[PSCustomObject]@{
    Name              = $Me.displayName
    UserPrincipalName = $Me.userPrincipalName
    ObjectId          = $Me.id
} | Format-List

# ============================================================================
# GRAPH CONTEXT
# ============================================================================

Write-Section "GRAPH SESSION"

$GraphContext = Get-MgContext

[PSCustomObject]@{
    Account  = $GraphContext.Account
    TenantId = $GraphContext.TenantId
    Scopes   = ($GraphContext.Scopes -join ", ")
} | Format-List

# ============================================================================
# LOAD ENTRA ROLE DEFINITIONS
# ============================================================================

try {

    $EntraRoleDefinitions = @(
        Invoke-GraphPagedRequest `
            -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$select=id,templateId,displayName,description,isBuiltIn,rolePermissions"
    )

}
catch {

    Write-Host ""
    Write-Host "WARNING: Could not read Entra role definitions." `
        -ForegroundColor Yellow

    Write-Host $_.Exception.Message -ForegroundColor DarkGray

    $EntraRoleDefinitions = @()
}

# ============================================================================
# TRANSITIVE MEMBERSHIPS
# ============================================================================

Write-Section "TRANSITIVE ENTRA MEMBERSHIPS"

try {

    $Memberships = @(
        Invoke-GraphPagedRequest `
            -Uri "https://graph.microsoft.com/v1.0/me/transitiveMemberOf"
    )

}
catch {

    Write-Host ""
    Write-Host "Unable to retrieve transitive memberships." `
        -ForegroundColor Red

    Write-Host $_.Exception.Message -ForegroundColor Red

    $Memberships = @()
}

$ResolvedMemberships = foreach ($Membership in $Memberships) {

    $ODataType = Get-SafePropertyValue `
        -Object $Membership `
        -PropertyName "@odata.type"

    switch ($ODataType) {

        "#microsoft.graph.group" {

            $Name = Get-SafePropertyValue `
                -Object $Membership `
                -PropertyName "displayName"

            $Description = Get-SafePropertyValue `
                -Object $Membership `
                -PropertyName "description"

            $SecurityEnabled = Get-SafePropertyValue `
                -Object $Membership `
                -PropertyName "securityEnabled"

            # Limited information fallback
            if (-not $Name) {

                try {

                    $GroupDetails = Invoke-MgGraphRequest `
                        -Method GET `
                        -Uri "https://graph.microsoft.com/v1.0/groups/$($Membership.id)?`$select=id,displayName,description,securityEnabled" `
                        -OutputType PSObject `
                        -ErrorAction Stop

                    $Name = Get-SafePropertyValue `
                        -Object $GroupDetails `
                        -PropertyName "displayName"

                    $Description = Get-SafePropertyValue `
                        -Object $GroupDetails `
                        -PropertyName "description"

                    $SecurityEnabled = Get-SafePropertyValue `
                        -Object $GroupDetails `
                        -PropertyName "securityEnabled"

                }
                catch {
                }
            }

            if (-not $Name) {
                $Name = "<Unable to resolve>"
            }

            [PSCustomObject]@{
                Type            = "Group"
                Name            = $Name
                ObjectId        = $Membership.id
                SecurityEnabled = $SecurityEnabled
                Description     = $Description
            }
        }

        "#microsoft.graph.directoryRole" {

            Resolve-DirectoryRole `
                -Membership $Membership `
                -RoleDefinitions $EntraRoleDefinitions
        }

        default {

            [PSCustomObject]@{
                Type            = $ODataType
                Name            = Get-SafePropertyValue `
                    -Object $Membership `
                    -PropertyName "displayName"

                ObjectId        = $Membership.id
                SecurityEnabled = $null

                Description     = Get-SafePropertyValue `
                    -Object $Membership `
                    -PropertyName "description"
            }
        }
    }
}

$ResolvedMemberships = @($ResolvedMemberships)

$Groups = @(
    $ResolvedMemberships |
        Where-Object Type -eq "Group"
)

$DirectoryRoles = @(
    $ResolvedMemberships |
        Where-Object Type -eq "Entra Directory Role"
)

if ($ResolvedMemberships.Count -gt 0) {

    $ResolvedMemberships |
        Sort-Object Type, Name |
        Format-Table `
            @{Label="Type";Expression={$_.Type};Width=23},
            @{Label="Name";Expression={$_.Name};Width=42},
            @{Label="Object ID";Expression={$_.ObjectId};Width=38},
            @{Label="Security";Expression={$_.SecurityEnabled};Width=8},
            @{Label="Description";Expression={$_.Description};Width=60} `
            -Wrap

}
else {

    Write-Host "No memberships returned." -ForegroundColor DarkYellow
}

# ============================================================================
# SECURITY / DEFENDER GROUPS
# ============================================================================

Write-Section "LIKELY DEFENDER / SECURITY ROLE GROUPS"

$SecurityGroups = @(
    $Groups |
        Where-Object {
            $_.Name -match $DefenderGroupPattern
        } |
        Sort-Object Name
)

if ($SecurityGroups.Count -gt 0) {

    $SecurityGroups |
        Format-Table `
            @{Label="Group";Expression={$_.Name};Width=45},
            @{Label="Object ID";Expression={$_.ObjectId};Width=38},
            @{Label="Description";Expression={$_.Description};Width=60} `
            -Wrap

}
else {

    Write-Host "No group names matching the Defender/Security filter were found." `
        -ForegroundColor DarkYellow
}

# ============================================================================
# ENTRA DIRECTORY ROLES
# ============================================================================

Write-Section "ENTRA DIRECTORY ROLES"

if ($DirectoryRoles.Count -gt 0) {

    $DirectoryRoles |
        Sort-Object Name |
        Format-Table `
            @{Label="Role";Expression={$_.Name};Width=40},
            @{Label="Object ID";Expression={$_.ObjectId};Width=38},
            @{Label="Description";Expression={$_.Description};Width=70} `
            -Wrap

}
else {

    Write-Host "No Entra directory roles were found." `
        -ForegroundColor DarkGray
}

# ============================================================================
# DEFENDER UNIFIED RBAC
# ============================================================================

Write-Section "DEFENDER XDR UNIFIED RBAC"

try {

    $DefenderRoleDefinitions = @(
        Invoke-GraphPagedRequest `
            -Uri "https://graph.microsoft.com/beta/roleManagement/defender/roleDefinitions"
    )

    $DefenderRoleAssignments = @(
        Invoke-GraphPagedRequest `
            -Uri "https://graph.microsoft.com/beta/roleManagement/defender/roleAssignments"
    )

    Write-Host "Defender RBAC API access successful." `
        -ForegroundColor Green

}
catch {

    Write-Host "Could not read Defender Unified RBAC configuration." `
        -ForegroundColor Yellow

    Write-Host $_.Exception.Message -ForegroundColor DarkGray

    $DefenderRoleDefinitions = @()
    $DefenderRoleAssignments = @()
}

# ============================================================================
# DEFENDER ROLE DEFINITIONS
# ============================================================================

Write-Section "DEFENDER ROLE DEFINITIONS"

if ($DefenderRoleDefinitions.Count -gt 0) {

    $DefenderRoleDefinitions |
        Sort-Object displayName |
        ForEach-Object {

            [PSCustomObject]@{
                RoleName    = $_.displayName
                RoleId      = $_.id
                Description = $_.description
            }

        } |
        Format-Table `
            @{Label="Role";Expression={$_.RoleName};Width=40},
            @{Label="Role ID";Expression={$_.RoleId};Width=38},
            @{Label="Description";Expression={$_.Description};Width=70} `
            -Wrap

}
else {

    Write-Host "No Defender role definitions returned." `
        -ForegroundColor DarkGray
}

# ============================================================================
# DEFENDER ROLE PERMISSIONS
# ============================================================================

Write-Section "DEFENDER ROLE PERMISSIONS"

foreach ($Role in ($DefenderRoleDefinitions | Sort-Object displayName)) {

    Write-Host ""
    Write-Host $Role.displayName -ForegroundColor Cyan

    Write-Host "Role ID: " -NoNewline -ForegroundColor DarkGray
    Write-Host $Role.id -ForegroundColor DarkGray

    if ($Role.description) {
        Write-Host "Description: $($Role.description)" `
            -ForegroundColor DarkGray
    }

    $Permissions = @(
        Get-DefenderRolePermissions `
            -RoleDefinition $Role
    )

    if ($Permissions.Count -gt 0) {

        foreach ($Permission in $Permissions) {
            Write-Host "  + $Permission" -ForegroundColor Green
        }

    }
    else {

        Write-Host "  <No allowedResourceActions returned>" `
            -ForegroundColor DarkGray
    }
}

# ============================================================================
# INSPECT DEFENDER ASSIGNMENT SCHEMA
# ============================================================================

Write-Section "DEFENDER ROLE ASSIGNMENT STRUCTURE"

if ($DefenderRoleAssignments.Count -gt 0) {

    Write-Host "Assignments returned: $($DefenderRoleAssignments.Count)" `
        -ForegroundColor Cyan

    Write-Host ""
    Write-Host "Properties returned by the first assignment:" `
        -ForegroundColor DarkGray

    $DefenderRoleAssignments[0].PSObject.Properties.Name |
        Sort-Object |
        ForEach-Object {
            Write-Host "  $_"
        }

}
else {

    Write-Host "No Defender role assignments returned." `
        -ForegroundColor DarkGray
}

# ============================================================================
# CORRELATE USER / GROUP IDS WITH DEFENDER ASSIGNMENTS
# ============================================================================

Write-Section "EFFECTIVE DEFENDER ROLE ASSIGNMENTS"

$EffectivePrincipalIds = @(
    $Me.id

    $Groups |
        Select-Object -ExpandProperty ObjectId
) | Sort-Object -Unique

foreach ($Assignment in $DefenderRoleAssignments) {

    $PrincipalIds = [System.Collections.Generic.List[string]]::new()

    #
    # Try common schemas defensively.
    #

    $SinglePrincipalId = Get-SafePropertyValue `
        -Object $Assignment `
        -PropertyName "principalId"

    if ($SinglePrincipalId) {
        $PrincipalIds.Add([string]$SinglePrincipalId)
    }

    $MultiplePrincipalIds = Get-SafePropertyValue `
        -Object $Assignment `
        -PropertyName "principalIds"

    foreach ($PrincipalId in @($MultiplePrincipalIds)) {

        if ($PrincipalId) {
            $PrincipalIds.Add([string]$PrincipalId)
        }
    }

    #
    # Some Defender assignment structures contain authorizationSystemInfo
    # or other nested objects. Check common nested properties as well.
    #

    $PrincipalsProperty = Get-SafePropertyValue `
        -Object $Assignment `
        -PropertyName "principals"

    foreach ($PrincipalObject in @($PrincipalsProperty)) {

        if ($null -eq $PrincipalObject) {
            continue
        }

        $NestedPrincipalId = Get-SafePropertyValue `
            -Object $PrincipalObject `
            -PropertyName "id"

        if ($NestedPrincipalId) {
            $PrincipalIds.Add([string]$NestedPrincipalId)
        }

        $NestedPrincipalId = Get-SafePropertyValue `
            -Object $PrincipalObject `
            -PropertyName "principalId"

        if ($NestedPrincipalId) {
            $PrincipalIds.Add([string]$NestedPrincipalId)
        }
    }

    $PrincipalIds = @(
        $PrincipalIds |
            Sort-Object -Unique
    )

    $MatchingPrincipal = $PrincipalIds |
        Where-Object {
            $_ -in $EffectivePrincipalIds
        } |
        Select-Object -First 1

    if (-not $MatchingPrincipal) {
        continue
    }

    # ------------------------------------------------------------------------
    # Resolve source principal
    # ------------------------------------------------------------------------

    if ($MatchingPrincipal -eq $Me.id) {

        $SourceName = "Direct user assignment"
        $SourceType = "User"

    }
    else {

        $MatchingGroup = $Groups |
            Where-Object ObjectId -eq $MatchingPrincipal |
            Select-Object -First 1

        if ($MatchingGroup) {
            $SourceName = $MatchingGroup.Name
        }
        else {
            $SourceName = $MatchingPrincipal
        }

        $SourceType = "Entra Group"
    }

    # ------------------------------------------------------------------------
    # Resolve Defender role
    # ------------------------------------------------------------------------

    $RoleDefinitionId = Get-SafePropertyValue `
        -Object $Assignment `
        -PropertyName "roleDefinitionId"

    $RoleDefinition = $null

    if ($RoleDefinitionId) {

        $RoleDefinition = $DefenderRoleDefinitions |
            Where-Object id -eq $RoleDefinitionId |
            Select-Object -First 1
    }

    $RoleName = if ($RoleDefinition) {
        $RoleDefinition.displayName
    }
    elseif ($RoleDefinitionId) {
        "<Unknown role: $RoleDefinitionId>"
    }
    else {
        "<RoleDefinitionId not returned>"
    }

    $AssignmentName = Get-SafePropertyValue `
        -Object $Assignment `
        -PropertyName "displayName"

    if (-not $AssignmentName) {
        $AssignmentName = Get-SafePropertyValue `
            -Object $Assignment `
            -PropertyName "name"
    }

    if (-not $AssignmentName) {
        $AssignmentName = "<No assignment name>"
    }

    $Permissions = @()

    if ($RoleDefinition) {

        $Permissions = @(
            Get-DefenderRolePermissions `
                -RoleDefinition $RoleDefinition
        )
    }

    $EffectiveAssignments += [PSCustomObject]@{
        SourceType       = $SourceType
        SourceName       = $SourceName
        PrincipalId      = $MatchingPrincipal
        DefenderRole     = $RoleName
        RoleDefinitionId = $RoleDefinitionId
        AssignmentName   = $AssignmentName
        Permissions      = $Permissions
    }
}

# ============================================================================
# EFFECTIVE ASSIGNMENT TABLE
# ============================================================================

if ($EffectiveAssignments.Count -gt 0) {

    $EffectiveAssignments |
        Sort-Object SourceName, DefenderRole |
        Format-Table `
            @{Label="Granted through";Expression={$_.SourceName};Width=40},
            @{Label="Type";Expression={$_.SourceType};Width=15},
            @{Label="Defender Role";Expression={$_.DefenderRole};Width=40},
            @{Label="Assignment";Expression={$_.AssignmentName};Width=40} `
            -Wrap

}
else {

    Write-Host ""
    Write-Host "No Defender assignment could be correlated with the user or his groups." `
        -ForegroundColor Yellow

    Write-Host ""
    Write-Host "Important:" -ForegroundColor Yellow

    Write-Host @"
This can mean either:

  1. The user really has no matching Defender Unified RBAC assignment.

  2. Defender returned a role-assignment schema with principal information
     in a different property.

The 'DEFENDER ROLE ASSIGNMENT STRUCTURE' section above shows the actual
property names returned by your tenant.
"@ -ForegroundColor DarkGray
}

# ============================================================================
# DETAILED EFFECTIVE PERMISSIONS
# ============================================================================

Write-Section "EFFECTIVE DEFENDER PERMISSIONS"

if ($EffectiveAssignments.Count -gt 0) {

    foreach ($Item in $EffectiveAssignments) {

        Write-Host ""
        Write-Host "------------------------------------------------------------" `
            -ForegroundColor DarkGray

        Write-Host "Granted through : " -NoNewline
        Write-Host $Item.SourceName -ForegroundColor Cyan

        Write-Host "Principal type  : " -NoNewline
        Write-Host $Item.SourceType

        Write-Host "Principal ID    : " -NoNewline
        Write-Host $Item.PrincipalId -ForegroundColor DarkGray

        Write-Host "Defender role   : " -NoNewline
        Write-Host $Item.DefenderRole -ForegroundColor Green

        Write-Host "Role ID         : " -NoNewline
        Write-Host $Item.RoleDefinitionId -ForegroundColor DarkGray

        Write-Host ""
        Write-Host "Permissions:" -ForegroundColor Yellow

        if (@($Item.Permissions).Count -gt 0) {

            foreach ($Permission in $Item.Permissions) {
                Write-Host "  + $Permission" -ForegroundColor Green
            }

        }
        else {

            Write-Host "  <No permissions returned>" `
                -ForegroundColor DarkGray
        }
    }
}
else {

    Write-Host "No effective Defender assignments resolved." `
        -ForegroundColor DarkGray
}

# ============================================================================
# SUMMARY
# ============================================================================

Write-Host ""
Write-Host "============================================================" `
    -ForegroundColor DarkCyan

Write-Host " SUMMARY" `
    -ForegroundColor Cyan

Write-Host "============================================================" `
    -ForegroundColor DarkCyan

[PSCustomObject]@{
    User                    = $Me.userPrincipalName
    TotalMemberships        = $ResolvedMemberships.Count
    Groups                  = $Groups.Count
    EntraDirectoryRoles     = $DirectoryRoles.Count
    SecurityRelatedGroups   = $SecurityGroups.Count
    DefenderRoleDefinitions = $DefenderRoleDefinitions.Count
    DefenderRoleAssignments = $DefenderRoleAssignments.Count
    EffectiveAssignments    = $EffectiveAssignments.Count
} | Format-List

Write-Host ""
Write-Host "Check complete." -ForegroundColor Green