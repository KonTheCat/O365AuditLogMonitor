param (
    [object]
    $WebhookData
)

#variables
$ResourceGroup = 'TestO365AuditLogMonitor'
$StorageAccountName = 'TestO365AuditLogMonitor'
$TableName = 'AuditLogActionsLog'
$RemoteCredential = Get-AutomationPSCredential -name 'delegatedadmin'

#Variables for storage  
$Conn = Get-AutomationConnection -Name AzureRunAsConnection
Connect-AzureRmAccount -ServicePrincipal -Tenant $Conn.TenantID -ApplicationId $Conn.ApplicationID -CertificateThumbprint $Conn.CertificateThumbprint
$context = (Get-AzureRmStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroup).context
$table = Get-AzureStorageTable -Name $TableName -Context $context

$requestBody = ConvertFrom-Json $WebhookData.RequestBody
$domain = $requestBody.domain 
$user = $requestBody.user
$ID = $requestBody.ID

Write-Output "Securing account $user at $domain, from activity in log $ID"

#login to O365 tennant 
$RemoteSession = New-PSSession -ConfigurationName Microsoft.Exchange `
                               -ConnectionUri ('https://ps.outlook.com/powershell-liveid?DelegatedOrg=' + $domain) `
                               -Credential $RemoteCredential `
                               -Authentication Basic `
                               -AllowRedirection

Import-Module (Import-PSSession $RemoteSession -AllowClobber -DisableNameChecking) -Global -DisableNameChecking
Connect-MsolService -Credential $RemoteCredential
$TennantGuid = Get-MsolPartnerContract | Where-Object {$_.DefaultDomainName -eq "$domain"} | Select-Object -ExpandProperty TenantId | Select-Object -ExpandProperty GUID

#mailbox actions
$newPassword = ([System.Web.Security.Membership]::GeneratePassword(16,2))
Set-MsolUserPassword –UserPrincipalName $user –NewPassword $newPassword -ForceChangePassword $True -TenantId $TennantGuid
Write-Output "We've set the password for the account $user to be $newPassword. It will need to be reset on logon."
Set-MsolUser -UserPrincipalName $user -BlockCredential $true -TenantId $TennantGuid
Set-CASMailbox -Identity $user -OWAEnabled $false

Write-Output "Printing the properties of the mailbox below"
Get-Mailbox -Identity $user | Format-List -Property *

Write-Output "Printing the rules of the mailbox below"
Get-InboxRule -Mailbox $user | Format-List -Property * 

Write-Output "Removing all mailbox forwards."
Set-Mailbox -Identity $user -DeliverToMailboxAndForward $false -ForwardingSmtpAddress $null

Write-Output "Disabling all mailbox rules."
Get-InboxRule -Mailbox $user | Disable-InboxRule -Confirm:$false

#log to the database
$props = @{
    'RanRemediateAccountRunbook' = "$True"
    'User' = "$user"
}
Add-StorageTableRow -table $table -partitionKey $domain -rowKey $ID -property $props
