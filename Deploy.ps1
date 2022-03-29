Connect-AzureAD
az login

$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$PasswordProfile.Password = "%cP&KCuC48YEYs3l3t9o!fIJU"
$PasswordProfile.ForceChangePasswordNextLogin = $false

New-AzureADUser -DisplayName "nfp" -PasswordProfile $PasswordProfile `
-UserPrincipalName "nfp@adsikkerhed.dk" -AccountEnabled $true `
-MailNickName "nfp"

New-AzureADUser -DisplayName "AppOwner" -PasswordProfile $PasswordProfile `
-UserPrincipalName "AppOwner@adsikkerhed.dk" -AccountEnabled $true `
-MailNickName "AppOwner"

New-AzureADUser -DisplayName "privadmin" -PasswordProfile $PasswordProfile `
-UserPrincipalName "privadmin@adsikkerhed.dk" -AccountEnabled $true `
-MailNickName "privadmin"

New-AzureADUser -DisplayName "AutomationAdmin" -PasswordProfile $PasswordProfile `
-UserPrincipalName "AutomationAdmin@adsikkerhed.dk" -AccountEnabled $true `
-MailNickName "AutomationAdmin"

[pscustomobject]@{ username =  'nfp@adsikkerhed.dk'; password = '%cP&KCuC48YEYs3l3t9o!fIJU'; } | `
Export-Csv -Path .\test.csv -Append -NoTypeInformation -delimiter ";" -Encoding UTF8

$resourceGroup = "STORAGE"
$location = "northeurope"
New-AzResourceGroup -Name $resourceGroup -Location $location

$StorageAccountProv = @{
  ResourceGroupName       = $resourceGroup
  Name                    = 'adsikkerhed'
  SkuName                 = 'Standard_LRS'
  Location                = $location
  EnableHttpsTrafficOnly  = $false
}
$StorageAccount = New-AzStorageAccount @StorageAccountProv
$Context = $StorageAccount.Context

$ContainerName = 'files'
New-AzStorageContainer -Name $ContainerName -Context `
$Context -Permission Container

$TestCSV = @{
  File             = '.\test.csv'
  Container        = $ContainerName
  Blob             = "test.csv"
  Context          = $Context
  StandardBlobTier = 'Hot'
}
Set-AzStorageBlobContent @TestCSV

Import-Module AzureADPreview -Force
New-AzureADMSGroup -DisplayName "AutomationAdmins" -Description `
"This dynamic group will add any AAD user with 'automationadmin' in Display Name" `
-MailEnabled $False -MailNickName "AutomationAdmins" -SecurityEnabled $True `
-GroupTypes "DynamicMembership" -MembershipRule `
'(user.displayName -contains "automationadmin")' `
-MembershipRuleProcessingState "On"

$AutomationAdminsID = (Get-AzADGroup -DisplayName AutomationAdmins).id
New-AzRoleAssignment -ObjectId $AutomationAdminsID `
-RoleDefinitionName "Automation Contributor"


az ad sp create-for-rbac --name VMContributor --role "Virtual Machine Contributor"

$resourceGroup = "AUTOMATION"
$location = "northeurope"
New-AzResourceGroup -Name $resourceGroup -Location $location

New-AzAutomationAccount -Name "AutomationAccount" -Location $location -ResourceGroupName $resourceGroup

$params = @{
    AutomationAccountName = 'AutomationAccount'
    Name                  = 'RunBookPowerShell'
    ResourceGroupName     = 'AUTOMATION'
    Type                  = 'PowerShell'
    Path                  = '.\VMContribScript.ps1'
}
Import-AzAutomationRunbook @params

$rgName = 'VMRG'
$location = 'northeurope'
New-AzResourceGroup -Name $rgName -Location $location

## Create IP. ##
$ip = @{
    Name = 'AZVMPUBLICIP'
    ResourceGroupName = $rgName
    Location = $location
    Sku = 'Standard'
    AllocationMethod = 'Static'
    IpAddressVersion = 'IPv4'
    Zone = 1,2,3   
}

New-AzPublicIpAddress @ip

# Create a Virtual Machine
$vmName = 'AZHACK'
$userName = 'rootnation'
$plainTextPassword = '6#d_PL)tC@%2D[N'
$securePassword = $plainTextPassword | ConvertTo-SecureString -AsPlainText -Force
$credential = [pscredential]::new($userName, $securePassword)
$vm = New-AzVM -ResourceGroupName $rgName -Name $vmName `
-Location $location -Credential $credential -PublicIpAddressName 'AZVMPUBLICIP'

#Allow all inbound to VM
Get-AzNetworkSecurityGroup -Name $vmName -ResourceGroupName $rgName `
| Add-AzNetworkSecurityRuleConfig -Name "ALL" -Description "Allow all ports" `
-Access "Allow" -Protocol "Tcp" -Direction "Inbound" -Priority 100 `
-SourceAddressPrefix "*" -SourcePortRange "*" -DestinationAddressPrefix "*" `
-DestinationPortRange "*" | Set-AzNetworkSecurityGroup

Install-Module -Name Az.ManagedServiceIdentity -Scope CurrentUser -Force
$identityName = 'AZHACKManagedIdentity'
$identity = New-AzUserAssignedIdentity -Name $identityName `
-ResourceGroupName $rgName -Location $location

$keyVaultName = 'ADSIKKERHED'
$keyVault = New-AzKeyVault -ResourceGroupName $rgName `
-Name $keyVaultName -Location $location

$secretValue = ConvertTo-SecureString -String $PasswordProfile.Password -AsPlainText -Force
Set-AzKeyVaultSecret -VaultName $keyVaultName `
-Name AppOwner -SecretValue $secretValue


New-AzRoleAssignment -RoleDefinitionName Reader `
-Scope $keyVault.ResourceId -ObjectId $identity.PrincipalId


Set-AzKeyVaultAccessPolicy -ResourceGroupName $rgName -VaultName $keyVaultName `
-ServicePrincipalName $identity.ClientId -PermissionsToSecrets get,list

Update-AzVM -ResourceGroupName $rgName -VM $vm `
-IdentityType UserAssigned -IdentityID $identity.Id

Write-Host "Continue App Registration in GUI"
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

$ObjectID = Get-AzureADApplication -Filter "DisplayName eq 'HackingApp'" `
| Select-Object ObjectID
$RefObjectId = Get-AzureADUser -Filter `
"userPrincipalName eq 'AppOwner@adsikkerhed.dk'" | Select-Object ObjectID
Add-AzureADApplicationOwner -ObjectId $ObjectID.ObjectId  -RefObjectId $RefObjectId.ObjectId
$ObjectID = Get-AzureADServicePrincipal -SearchString HackingApp | Select-Object ObjectID
Add-AzureADServicePrincipalOwner -ObjectId $ObjectID.ObjectId -RefObjectId $RefObjectId.ObjectId

$user = Get-AzureADUser -Filter "userPrincipalName eq 'privadmin@adsikkerhed.dk'"
$roleDefinition = Get-AzureADMSRoleDefinition -Filter "displayName eq 'Privileged Role Administrator'"
$roleAssignment = New-AzureADMSRoleAssignment -DirectoryScopeId '/' `
-RoleDefinitionId $roleDefinition.Id -PrincipalId $user.objectId

$resourceGroup = "CLOUDSHELL"
$location = "northeurope"
New-AzResourceGroup -Name $resourceGroup -Location $location

New-AzRoleAssignment -ObjectId $user.ObjectId `
-RoleDefinitionName "Contributor" `
-ResourceGroupName $resourceGroup

New-AzRoleAssignment -ObjectId $user.ObjectId `
-RoleDefinitionName "Reader" `
-ResourceGroupName $resourceGroup

Write-Host "Finish Cloud Shell for privadmin in GUI"