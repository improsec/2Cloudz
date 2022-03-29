$user = 'VMContributor'
$pass = 'TDX3P4SKvg6WHKk4a_Ltko2w~dy.xKytdg' | ConvertTo-SecureString -AsPlainText -Force

$Credentials = New-Object System.Management.Automation.PSCredential $user,$pass

Start-Process -Credential $Credentials -FilePath C:\Windows\System32\calc.exe