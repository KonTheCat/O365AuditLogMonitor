param (
    [object]
    $WebhookData
)

#Variables 
$MinutesToGoBack = '180' #this is where you configure how far back into the admin log each
$FlowURI = 'webhook to flow'
$RemoteCredential = Get-AutomationPSCredential -name 'delegatedadmin'
$ResourceGroup = 'TestO365AuditLogMonitor'
$StorageAccountName = 'TestO365AuditLogMonitor'
$TableName = 'ProcessedAuditLogs'
$IPStackAPIKey = 'your webhook'

$requestBody = ConvertFrom-Json $WebhookData.RequestBody
Write-Output "Request received via webhook '$($WebhookData.WebhookName)' by '$($WebhookData.RequestHeader.From)' at $($WebhookData.RequestHeader.Date)"

$Domain = $requestBody | Select-Object -ExpandProperty Domain
Write-Output "$Domain - Checking Unfied Audit Log" 

$IDtoignore = $requestBody | Select-Object -ExpandProperty IDtoignore
if ($IDtoignore) {
    Write-Output "$IDtoignore are the IDs we will be ignoring."
    $IDtoignore = $IDtoignore.split(" ")
    Write-Output "There are $($IDtoignore.Count) IDs to ignore."
} else {
    Write-Output "There are no IDs to ignore"
}

#Variables for storage  
$Conn = Get-AutomationConnection -Name AzureRunAsConnection
Connect-AzureRmAccount -ServicePrincipal -Tenant $Conn.TenantID -ApplicationId $Conn.ApplicationID -CertificateThumbprint $Conn.CertificateThumbprint
$context = (Get-AzureRmStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroup).context
$table = Get-AzureStorageTable -Name $TableName -Context $context


#Functions 
function Get-RuleForAnalysis {
    [cmdletbinding()]
    Param (
    [parameter(ValueFromPipeline)]
    $Log
    )
    $Rule = Get-InboxRule -Mailbox $Log.UserId | Where-Object {$_.Name -eq ($Log.parameters |
        Where-Object {$_.Name -eq 'Name'} | Select-Object -ExpandProperty value)} | Select-Object -Property *
    Return $Rule
    }

function Get-RuleIsThreat {
    [cmdletbinding()]
    Param (
    [parameter(ValueFromPipeline)]
    $Rule
    )

    if ($null -eq $Rule) {
    Return "No rule found to do analysis of for $($Log.ID)"
    }
    #working with forwarding addresses 
    $Addresses = $Rule |  Select-Object -Property forwardto, forwardasattachmentto, redirectto
    If ($Addresses) {
    if ($Addresses.forwardto) {
        $Domains += ((($addresses.forwardto -split 'SMTP:')[1]).Replace(']','') -split '@')[1] + ';'
    }
    if ($addresses.forwardasattachmentto) {
        $Domains += ((($addresses.forwardasattachmentto -split 'SMTP:')[1]).Replace(']','') -split'@')[1] + ';'
    }
    if ($addresses.redirectto) {
        $Domains += ((($addresses.redirectto -split 'SMTP:')[1]).Replace(']','') -split '@')[1] + ';'
    }
    $RuleDomains = $Domains.Split(";",[System.StringSplitOptions]::RemoveEmptyEntries)
    $AcceptedDomains = (Get-AcceptedDomain).DomainName
    Foreach ($RuleDomain in $RuleDomains) {
        if ($AcceptedDomains -notcontains $RuleDomain) {
            $ExternalDomains += $RuleDomain + ';'
        }
    }
    $ForwardingThreat = $True
    } else {
        $ForwardingThreat = $false
    }
    #working with the description 
    $Description = $Rule.description
    if ($Description -notlike "*If the message*") {
        $DescriptionThreat = $True
    } else {
        $DescriptionThreat = $False
    }
    #working with deletion
    if ($Rule.DeleteMessage) {
        $DeleteThreat = $True
    } else {
        $DeleteThreat = $False
    }

    #threat determination logic
    if ($DeleteThreat -and $DescriptionThreat) {
        $Threat = $True
    } elseif ($ForwardingThreat) {
        $Threat = $True
    } else {
        $Threat = $false
    }

    $ReturnThreatTable = @{
        'Threat' = "$Threat"
        'ForwardingExternally' = "$ForwardingThreat"
        'AppliesAllMail' = "$DescriptionThreat"
        'Delete' = "$DeleteThreat"
        'Description' = "$($Rule.description)"
        'RuleId' = "$($Rule.RuleIdentity)"
    }

    Return $ReturnThreatTable
}

function Get-SetMailboxThreat {
    [cmdletbinding()]
    Param (
    [parameter(ValueFromPipeline)]
    $Log
    )

    $ForwardingAddress = $Log.parameters | Where-Object {$_.Name -eq 'ForwardingSmtpAddress'} | Select-Object -ExpandProperty value
    if ($ForwardingAddress) {
        $ForwardingDomain = ($ForwardingAddress -split '@')[1]
        if ($(Get-AcceptedDomain).DomainName -notcontains $ForwardingDomain) {
            $SetMailboxForwardingStatus = "The Set-Mailbox command in ID $($Log.ID) set forwarding to external domain $ForwardingDomain."
            $Threat = $True
        } Else {
            $SetMailboxForwardingStatus = "The Set-Mailbox command in ID $($Log.ID) set forwarding to non-external address $ForwardingAddress."
            $Threat = $False
        }
    }  Else {
        $SetMailboxForwardingStatus = "The Set-Mailbox command in ID $($Log.ID) did not make a forwarding change."
        $Threat = $False
    }

    $ReturnThreatTable = @{
        'Threat' = "$Threat"
        'SetMailboxForwardingStatus' = "$SetMailboxForwardingStatus"
        'ForwardingAddress' = "$ForwardingAddress"
    }

    return $ReturnThreatTable
}


function Send-ToFlow {
    [cmdletbinding()]
    Param (
    [parameter(ValueFromPipeline)]
    $ThreatTable
    )
    $uri = $FlowURI

    $body = ConvertTo-Json -InputObject $ThreatTable
    $body
    Invoke-RestMethod -Method Post -Uri $uri -Body $body -ContentType application/json
}

function Get-LocationFromIP {
    [cmdletbinding()]
    Param (
    [parameter(ValueFromPipeline)]
    $IPAddress
    )

    switch ($IPAddress.Split(":").count) {
        1 {$IPAddress = $IPAddress}
        2 {$IPAddress = $IPAddress.Split(":")[0]}
        {$_ -gt 2} {$IPAddress = $IPAddress}
        Default {
            $Location = "Unable to determine the location, issues with determining IP address type"
            Return $Location
        }
    }
    
    $Result = Invoke-WebRequest -Uri "http://api.ipstack.com/$IPAddress`?access_key=$IPStackAPIKey" -UseBasicParsing
    if ($Result.StatusCode -ne '200') {
        $Location = "Unable to determine the location, bad status code"
        Return $Location   
    }

    $ResultContent = $Result.Content | ConvertFrom-json
    if ($ResultContent.type) {
        $Location = "$($ResultContent.city), $($ResultContent.region_name), $($ResultContent.country_name)"
        Return $Location
    } else {
        $Location = "Unable to determine the location, bad content"
        Return $Location
    }

}

#Main
$RemoteSession = New-PSSession -ConfigurationName Microsoft.Exchange `
                               -ConnectionUri ('https://ps.outlook.com/powershell-liveid?DelegatedOrg=' + $domain) `
                               -Credential $RemoteCredential `
                               -Authentication Basic `
                               -AllowRedirection 

Import-Module (Import-PSSession $RemoteSession -AllowClobber -DisableNameChecking) -Global -DisableNameChecking

#in testing, the listed 3 operations were found to be potentially indicative of malitious rules or forwarding setup 
$LogsForAnalysis = Search-UnifiedAuditLog -StartDate ((Get-Date).AddMinutes(-$MinutesToGoBack)) -EndDate (Get-Date) -Operations New-InboxRule,Set-InboxRule,Set-Mailbox |
Select-Object -ExpandProperty AuditData | Convertfrom-json | Where-Object {$_.UserId -ne 'NT AUTHORITY\SYSTEM (Microsoft.Exchange.ServiceHost)'} 

if ($LogsForAnalysis) {
    $LogCount = $LogsForAnalysis.count
    Write-Output "$LogCount Logs to parce, continuing execution."
} else {
    Write-Output "No matching logs to read, exiting runbook."
    exit
}

#determine needful processing depending on operation type 
foreach ($Log in $LogsForAnalysis) {

    if ($IDtoignore -notcontains $($Log.ID)) {

        $Location = $Log.ClientIP | Get-LocationFromIP

        switch ($log.Operation) {
            'New-InboxRule' {Write-Output "$($Log.ID) is the log entry's ID. It is a new inbox rule."
                            $ThreatTable = $Log | Get-RuleForAnalysis | Get-RuleIsThreat 
                            $ThreatTable.Add("SourceMailbox","$($Log.UserId)")
                            $ThreatTable.Add("Organization","$((Get-OrganizationConfig).displayname)")
                            $ThreatTable.Add("Type","InboxRule")
                            $ThreatTable.Add("LogID","$($Log.ID)")
                            $ThreatTable.Add("InternalTimeStamp","$($(Get-Date).tofiletimeutc())")
                            $ThreatTable.Add("ManagementDomain","$domain")
                            $ThreatTable.Add("IP","$($Log.ClientIP)")
                            $ThreatTable.Add("Location","$($Location)")

                            Add-StorageTableRow -table $table -partitionKey $domain -rowKey $($Log.ID) -property $ThreatTable

                                if ($ThreatTable.Threat -eq $true) {
                                    $ThreatTable | Send-ToFlow
                                }
                            } 
            'Set-InboxRule' {Write-Output "$($Log.ID) is the log entry's ID. it is a change to an inbox rule"
                            $ThreatTable = $Log | Get-RuleForAnalysis | Get-RuleIsThreat
                            $ThreatTable.Add("SourceMailbox","$($Log.UserId)")
                            $ThreatTable.Add("Organization","$((Get-OrganizationConfig).displayname)") 
                            $ThreatTable.Add("Type","InboxRule")
                            $ThreatTable.Add("LogID","$($Log.ID)")
                            $ThreatTable.Add("InternalTimeStamp","$($(Get-Date).tofiletimeutc())")
                            $ThreatTable.Add("ManagementDomain","$domain")
                            $ThreatTable.Add("IP","$($Log.ClientIP)")
                            $ThreatTable.Add("Location","$($Location)")

                            Add-StorageTableRow -table $table -partitionKey $domain -rowKey $($Log.ID) -property $ThreatTable

                                if ($ThreatTable.Threat -eq $true) {
                                    $ThreatTable | Send-ToFlow
                                }
                            }
            'Set-Mailbox' {Write-Output "$($Log.ID) is the log entry's ID. It is a change to the mailbox."
                            $ThreatTable = $Log | Get-SetMailboxThreat
                            $ThreatTable.Add("SourceMailbox","$($Log.UserId)")
                            $ThreatTable.Add("Organization","$((Get-OrganizationConfig).displayname)")
                            $ThreatTable.Add("Type","InboxForward")
                            $ThreatTable.Add("LogID","$($Log.ID)")
                            $ThreatTable.Add("InternalTimeStamp","$($(Get-Date).tofiletimeutc())")
                            $ThreatTable.Add("ManagementDomain","$domain")
                            $ThreatTable.Add("IP","$($Log.ClientIP)")
                            $ThreatTable.Add("Location","$($Location)")
                            
                            Add-StorageTableRow -table $table -partitionKey $domain -rowKey $($Log.ID) -property $ThreatTable

                                if ($ThreatTable.Threat -eq $true) {
                                    $ThreatTable | Send-ToFlow
                                }
                            }
            default {Write-Output "$($Log.ID) is the log entry's ID. We were not able to determine the Operation. This should not happen."}
    
        }
    } else {
        Write-Output "$($Log.ID) has already been processed. We will not process it again."
    }
}

Get-PSSession | Remove-PSSession
