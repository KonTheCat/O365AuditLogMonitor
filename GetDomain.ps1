#This runbook gets the domains accessible with partner account and kicks off the runbook that will search the audit log, per domain.
#It also fetches the IDs of the logs reported on over the last 12 hours and excludes those from being reported on. 

$Conn = Get-AutomationConnection -Name AzureRunAsConnection
Connect-AzureRmAccount -ServicePrincipal -Tenant $Conn.TenantID -ApplicationId $Conn.ApplicationID -CertificateThumbprint $Conn.CertificateThumbprint
$context = (Get-AzureRmStorageAccount -Name testo365auditlogmonitor -ResourceGroupName TestO365AuditLogMonitor).context
$table = Get-AzureStorageTable -Name ProcessedAuditLogs -Context $context
$timestampvalue = (Get-Date).AddHours(-12).ToFileTimeUtc()
[string]$filter = [Microsoft.WindowsAzure.Storage.Table.TableQuery]::GenerateFilterCondition("InternalTimeStamp",[Microsoft.WindowsAzure.Storage.Table.QueryComparisons]::GreaterThan,"$timestampvalue")
$IDtoignore = Get-AzureStorageTableRowByCustomFilter -table $table -customFilter $filter | Select-Object -ExpandProperty rowkey

$IDtoignore

$RemoteCredential = Get-AutomationPSCredential -name 'delegatedadmin'
Connect-MsolService -Credential $RemoteCredential
$domains = Get-MsolPartnerContract | Select-Object -ExpandProperty DefaultDomainName

#this part will kick off the rubook per-domain and feed in the log IDs to be ignored. 
Foreach ($domain in $domains) {
    $uri = "Webhook link for "
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
