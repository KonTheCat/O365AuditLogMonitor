#This runbook gets the domains accessible with partner account and kicks off the runbook that will search the audit log, per domain.
#It also fetches the IDs of the logs reported on over the last 12 hours and excludes those from being reported on. 

#variables
$RemoteCredential = Get-AutomationPSCredential -name 'delegatedadmin'
$ResourceGroup = 'TestO365AuditLogMonitor'
$StorageAccountName = 'TestO365AuditLogMonitor'
$TableName = 'ProcessedAuditLogs'
$HoursOldLogs = '-12'
$ProcessingRunbookWebhook = "webhook of ProcessAuditLog"

#azure table connection  
$Conn = Get-AutomationConnection -Name AzureRunAsConnection
Connect-AzureRmAccount -ServicePrincipal -Tenant $Conn.TenantID -ApplicationId $Conn.ApplicationID -CertificateThumbprint $Conn.CertificateThumbprint
$context = (Get-AzureRmStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroup).context
$table = Get-AzureStorageTable -Name $TableName -Context $context

#fetch logs
$timestampvalue = (Get-Date).AddHours($HoursOldLogs).ToFileTimeUtc()
[string]$filter = [Microsoft.WindowsAzure.Storage.Table.TableQuery]::GenerateFilterCondition("InternalTimeStamp",[Microsoft.WindowsAzure.Storage.Table.QueryComparisons]::GreaterThan,"$timestampvalue")
$IDtoignore = Get-AzureStorageTableRowByCustomFilter -table $table -customFilter $filter | Select-Object -ExpandProperty rowkey
if ($null -ne $IDtoignore) {
    Write-Output "Will ignore the following IDs - $IDtoignore"
}

#per domain, start runbook, send along the IDs to ignore 
Connect-MsolService -Credential $RemoteCredential
$domains = Get-MsolPartnerContract | Select-Object -ExpandProperty DefaultDomainName
Foreach ($domain in $domains) {
    $uri =  $ProcessingRunbookWebhook
    $headers = @{"From"="GetTenants_Start";"Date"=[DateTime]::Now.ToString("MM/dd/yyyy hh:mm:ss")}
    $details  = @{
        Domain = "$domain"
        IDtoignore = "$IDtoignore"
    }
    $body = ConvertTo-Json -InputObject $details
    $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body
    $jobid = $response.JobIds
    Write-Output -InputObject "The job ran with ID '$jobid'"
}
