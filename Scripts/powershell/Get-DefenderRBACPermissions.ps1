<#
.SYNOPSIS
    Shows the signed-in user's Entra group memberships and Defender-related
    RBAC information in a readable format.

.DESCRIPTION
    1. Signs in interactively with Microsoft Graph.
    2. Shows the currently signed-in user.
    3. Retrieves transitive group memberships (including nested groups).
    4. Highlights likely Defender / Security role groups.
    5. Attempts to query Microsoft Defender XDR Unified RBAC role definitions
       and assignments through Microsoft Graph Beta.

.NOTES
    Run this script while signed in as the user whose permissions you want
    to validate.

    Defender Unified RBAC Graph APIs currently use the Microsoft Graph
    beta endpoint and can change.
#>

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

$DefenderGroupPattern = '(?i)Defender|MDE|MDI|MDO|XDR|Security|SOC|Sentinel'

# ---------------------------------------------------------------------------
# Requirements
# ---------------------------------------------------------------------------

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host "Microsoft.Graph is not installed." -ForegroundColor Yellow
    Write-Host "Install it with:" -ForegroundColor Yellow
    Write-Host "Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Cyan
    return
}

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# ---------------------------------------------------------------------------
# Connect
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor DarkCyan
Write-Host " DEFENDER / ENTRA PERMISSION CHECK" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor DarkCyan
Write-Host ""

$Scopes = @(
    "User.Read",
    "RoleManagement.Read.Defender"
)

try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    Connect-MgGraph `
        -Scopes $Scopes `
        -NoWelcome `
        -ContextScope Process

}
catch {
    Write-Host "Graph login failed:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    return
}

# ---------------------------------------------------------------------------
# Helper: Graph pagination
# ---------------------------------------------------------------------------

function Invoke-GraphPagedRequest {

    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $Results = @()
    $NextUri = $Uri

    do {

        $Response = Invoke-MgGraphRequest `
            -Method GET `
            -Uri $NextUri `
            -OutputType PSObject

        # Graph collection response
        if ($Response.PSObject.Properties.Name -contains 'value') {
            $Results += @($Response.value)
        }
        else {
            # Single-object response
            $Results += $Response
        }

        # @odata.nextLink only exists if another page exists
        if ($Response.PSObject.Properties.Name -contains '@odata.nextLink') {
            $NextUri = $Response.'@odata.nextLink'
        }
        else {
            $NextUri = $null
        }

    } while ($NextUri)

    return $Results
}

# ---------------------------------------------------------------------------
# Current user
# ---------------------------------------------------------------------------

$Me = Invoke-MgGraphRequest `
    -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/me?`$select=id,displayName,userPrincipalName" `
    -OutputType PSObject

Write-Host "SIGNED-IN USER" -ForegroundColor Yellow
Write-Host "--------------"

[PSCustomObject]@{
    Name              = $Me.displayName
    UserPrincipalName = $Me.userPrincipalName
    ObjectId          = $Me.id
} | Format-List

# ---------------------------------------------------------------------------
# Transitive Entra memberships
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "TRANSITIVE ENTRA MEMBERSHIPS" -ForegroundColor Yellow
Write-Host "----------------------------"

$Memberships = Invoke-GraphPagedRequest `
    -Uri "https://graph.microsoft.com/v1.0/me/transitiveMemberOf?`$select=id,displayName,description"

$Groups = foreach ($Membership in $Memberships) {

    $Type = switch -Wildcard ($Membership.'@odata.type') {
        "*group" {
            "Group"
            break
        }

        "*directoryRole" {
            "Entra Directory Role"
            break
        }

        "*administrativeUnit" {
            "Administrative Unit"
            break
        }

        default {
            $Membership.'@odata.type'
        }
    }

    [PSCustomObject]@{
        Type        = $Type
        Name        = $Membership.displayName
        ObjectId    = $Membership.id
        Description = $Membership.description
    }
}

$Groups |
    Sort-Object Type, Name |
    Format-Table `
        @{Label="Type"; Expression={$_.Type}; Width=22},
        @{Label="Name"; Expression={$_.Name}; Width=45},
        @{Label="Object ID"; Expression={$_.ObjectId}; Width=38} `
        -AutoSize

# ---------------------------------------------------------------------------
# Defender / Security relevant groups
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "LIKELY DEFENDER / SECURITY ROLE GROUPS" -ForegroundColor Yellow
Write-Host "--------------------------------------"

$SecurityGroups = $Groups |
    Where-Object {
        $_.Type -eq "Group" -and
        $_.Name -match $DefenderGroupPattern
    } |
    Sort-Object Name

if ($SecurityGroups) {

    $SecurityGroups |
        Format-Table `
            @{Label="Group"; Expression={$_.Name}; Width=50},
            @{Label="Object ID"; Expression={$_.ObjectId}; Width=38},
            @{Label="Description"; Expression={$_.Description}; Width=60} `
            -Wrap

}
else {
    Write-Host "No group names matching the Defender/Security filter were found." `
        -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------------------
# Entra directory roles
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "ENTRA DIRECTORY ROLES" -ForegroundColor Yellow
Write-Host "---------------------"

$DirectoryRoles = $Groups |
    Where-Object {
        $_.Type -eq "Entra Directory Role"
    }

if ($DirectoryRoles) {

    $DirectoryRoles |
        Sort-Object Name |
        Format-Table Name, ObjectId -AutoSize

}
else {
    Write-Host "No directly visible Entra directory roles found." `
        -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Defender Unified RBAC
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "DEFENDER XDR UNIFIED RBAC" -ForegroundColor Yellow
Write-Host "-------------------------"

try {

    $RoleDefinitions = Invoke-GraphPagedRequest `
        -Uri "https://graph.microsoft.com/beta/roleManagement/defender/roleDefinitions"

    $RoleAssignments = Invoke-GraphPagedRequest `
        -Uri "https://graph.microsoft.com/beta/roleManagement/defender/roleAssignments"

    Write-Host "Defender RBAC API access successful." -ForegroundColor Green

    # IDs that may grant permissions to this user:
    # - user directly
    # - any group he belongs to
    $EffectivePrincipalIds = @(
        $Me.id
        $Groups |
            Where-Object Type -eq "Group" |
            Select-Object -ExpandProperty ObjectId
    )

    $EffectivePrincipalIds = $EffectivePrincipalIds | Select-Object -Unique

    $EffectiveAssignments = foreach ($Assignment in $RoleAssignments) {

        # Unified RBAC uses multiple principals in an assignment.
        $PrincipalIds = @()

        if ($Assignment.principalIds) {
            $PrincipalIds += $Assignment.principalIds
        }

        if ($Assignment.principalId) {
            $PrincipalIds += $Assignment.principalId
        }

        $MatchingPrincipal = $PrincipalIds |
            Where-Object {
                $_ -in $EffectivePrincipalIds
            } |
            Select-Object -First 1

        if (-not $MatchingPrincipal) {
            continue
        }

        $Role = $RoleDefinitions |
            Where-Object id -eq $Assignment.roleDefinitionId |
            Select-Object -First 1

        $SourceName = if ($MatchingPrincipal -eq $Me.id) {
            "Direct assignment"
        }
        else {
            ($Groups |
                Where-Object ObjectId -eq $MatchingPrincipal |
                Select-Object -First 1).Name
        }

        $Permissions = @()

        foreach ($PermissionSet in $Role.rolePermissions) {

            if ($PermissionSet.allowedResourceActions) {
                $Permissions += $PermissionSet.allowedResourceActions
            }
        }

        [PSCustomObject]@{
            SourceGroup    = $SourceName
            DefenderRole   = $Role.displayName
            AssignmentName = $Assignment.displayName
            Permissions    = ($Permissions -join "`n")
            RoleId         = $Role.id
        }
    }

    if ($EffectiveAssignments) {

        Write-Host ""
        Write-Host "EFFECTIVE DEFENDER ROLE ASSIGNMENTS" -ForegroundColor Green
        Write-Host ""

        $EffectiveAssignments |
            Sort-Object SourceGroup, DefenderRole |
            Format-Table `
                @{Label="Granted through"; Expression={$_.SourceGroup}; Width=40},
                @{Label="Defender role"; Expression={$_.DefenderRole}; Width=35},
                @{Label="Assignment"; Expression={$_.AssignmentName}; Width=35} `
                -Wrap

        Write-Host ""
        Write-Host "DETAILED PERMISSIONS" -ForegroundColor Green
        Write-Host ""

        foreach ($Item in $EffectiveAssignments) {

            Write-Host "------------------------------------------------------------" `
                -ForegroundColor DarkGray

            Write-Host "Source : " -NoNewline
            Write-Host $Item.SourceGroup -ForegroundColor Cyan

            Write-Host "Role   : " -NoNewline
            Write-Host $Item.DefenderRole -ForegroundColor Green

            Write-Host "Permissions:" -ForegroundColor Yellow

            $Item.Permissions -split "`n" |
                ForEach-Object {
                    Write-Host "  - $_"
                }
        }

    }
    else {

        Write-Host ""
        Write-Host "No Defender Unified RBAC assignments matched this user or his groups." `
            -ForegroundColor Yellow
    }

}
catch {

    Write-Host ""
    Write-Host "Could not read Defender Unified RBAC configuration." `
        -ForegroundColor Yellow

    Write-Host ""
    Write-Host "This does NOT necessarily mean the user has no Defender permissions." `
        -ForegroundColor Yellow

    Write-Host "Reason:" -ForegroundColor DarkGray
    Write-Host $_.Exception.Message -ForegroundColor DarkGray

    Write-Host ""
    Write-Host "The Entra group-membership results above are still valid." `
        -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "============================================================" -ForegroundColor DarkCyan
Write-Host " SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor DarkCyan

[PSCustomObject]@{
    User                    = $Me.userPrincipalName
    TotalMemberships        = $Groups.Count
    Groups                  = @($Groups | Where-Object Type -eq "Group").Count
    EntraDirectoryRoles     = @($DirectoryRoles).Count
    SecurityRelatedGroups   = @($SecurityGroups).Count
    DefenderRoleAssignments = @($EffectiveAssignments).Count
} | Format-List