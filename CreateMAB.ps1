$mac = "00000abb28fd"

$ErrorActionPreference = "Stop"

try {
    # Create user with temporary password
    $tempPws = ConvertTo-SecureString "TempPass123!" -AsPlainText -Force
    $user = New-ADUser -Name $mac -SamAccountName $mac -UserPrincipalName "$mac@viking.bm" -AccountPassword $tempPws -DisplayName $mac -Path "OU=Mab,DC=Domain,DC=local" -PassThru 
    
    # Get group with primary group token
    $group = Get-ADGroup "CN=MABGroup,OU=MAB,DC=Domain,DC=local" -Properties @("primaryGroupToken")
    
    # Add to group and set as primary
    Add-ADGroupMember -Identity $group -Members $user
    $user | Set-ADUser -Replace @{primaryGroupID = $group.primaryGroupToken}
    
    # Remove from Domain Users
    Get-ADGroup "domain users" | Remove-ADGroupMember -Members $user -Confirm:$False
    
    # Enable account
    $user | Enable-ADAccount
    
    # Set password after group membership
    $finalPws = ConvertTo-SecureString "$mac" -AsPlainText -Force
    Set-ADAccountPassword -Identity $user -Reset -NewPassword $finalPws
    
    Write-Host "MAC bypass user $mac created successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to create MAC bypass user: $_"
}
