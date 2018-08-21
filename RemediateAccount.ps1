#this remediates the account using data from O365 flow, Flow calls this via webhook. 

param (
    [object]
    $WebhookData
)
    $requestBody = ConvertFrom-Json $WebhookData.RequestBody
    $domain = $requestBody.domain 
    $user = $requestBody.user
    $ID = $requestBody.ID

Write-Output "Management domain, username, and audit log ID to process"
$domain  
$user  
$ID  

$ResourceGroup = 'TestO365AuditLogMonitor'
$StorageAccountName = 'TestO365AuditLogMonitor'
$TableName = 'AuditLogActionsLog'

#login and such 
$RemoteCredential = Get-AutomationPSCredential -name 'delegatedadmin'
$RemoteSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri ('https://ps.outlook.com/powershell-liveid?DelegatedOrg=' + $domain) -Credential $RemoteCredential -Authentication Basic -AllowRedirection 
Import-Module (Import-PSSession $RemoteSession -AllowClobber -DisableNameChecking) -Global -DisableNameChecking
Connect-MsolService -Credential $RemoteCredential
$TennantGuid = Get-MsolPartnerContract | Where-Object {$_.DefaultDomainName -eq "$domain"} | Select-Object -ExpandProperty TenantId | Select-Object -ExpandProperty GUID

#Variables for storage  
$Conn = Get-AutomationConnection -Name AzureRunAsConnection
Connect-AzureRmAccount -ServicePrincipal -Tenant $Conn.TenantID -ApplicationId $Conn.ApplicationID -CertificateThumbprint $Conn.CertificateThumbprint
$context = (Get-AzureRmStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroup).context
$table = Get-AzureStorageTable -Name $TableName -Context $context

#mailbox actions
$newPassword = ([System.Web.Security.Membership]::GeneratePassword(16,2))
Set-MsolUserPassword –UserPrincipalName $user –NewPassword $newPassword -ForceChangePassword $True -TenantId $TennantGuid
Write-Output "We've set the password for the account $user to be $newPassword. Make sure you record this and share with the user, or be ready to reset the password again. They will have to reset their password on the next logon."

Write-Output "We block the user account and disable owa."
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
