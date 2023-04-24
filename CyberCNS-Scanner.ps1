param([switch]$RenewCredentials)

$baseUri = "https://portaluseast2.mycybercns.com"

function Get-NewCredentials {
	$user = Read-Host "Enter API ClientID" -AsSecureString
	$pass = Read-Host "Enter API ClientSecret" -AsSecureString

	$textUser = ConvertFrom-SecureString $user -AsPlainText
	$textPass = ConvertFrom-SecureString $pass -AsPlainText
	$textPair = "${textUser}:${textPass}"


	$textBytes = [System.Text.Encoding]::ASCII.GetBytes($textPair)
	$textBase64 = [System.Convert]::ToBase64String($textBytes)
	$secureBase64 = ConvertTo-SecureString -AsPlainText -String $textBase64
	New-Item "C:\CyberCNS\Credentials.txt" -Value (ConvertFrom-SecureString -SecureString $secureBase64) -Force
	
	Clear-Variable text* -Scope Global	
	return ConvertFrom-SecureString -AsPlainText -SecureString $secureBase64
}

if ( (Test-Path "C:\CyberCNS\Credentials.txt") -and !$RenewCredentials) {
	try {
		$base64 = Get-Content "C:\CyberCNS\Credentials.txt" | ConvertTo-SecureString | ConvertFrom-SecureString -AsPlainText
	}
	catch {
		write-host -ForegroundColor Red "Error reading credential file at C:\CyberCNS\Credentials.txt`nGetting new credentials..."
		$base64 = Get-NewCredentials
	}
}
else {
	$base64 = Get-NewCredentials
}

$basicAuthValue = "Basic $base64"
 
$headers = @{ 
	'Content-Type'  = 'application/json'
	'customerid'    = 'enegren'
	'Authorization' = $basicAuthValue
}

$reqVals = Invoke-RestMethod "https://raw.githubusercontent.com/ECSJordan/CyberCNS-Scanner-Powershell/main/RequestValues.csv" | ConvertFrom-Csv
$reqQueries = $reqVals | Where-Object -Property type -Eq -Value "query"
$reqFields = $reqVals | Where-Object -Property type -Eq -Value "fields"

# Old reqQueries and reqFields:
# $reqQueries = @{
# 	disk       = '{"query":{"bool":{"must":[{"match":{"companyRef.id":"{{companyId}}"}},{"exists":{"field":"mountpoint"}},{"exists":{"field":"device"}}]}}}'
# 	passPolicy = '{"query":{"bool":{"must":[{"match":{"companyRef.id":"{{companyId}}"}},{"match":{"object_type":"ad_passwordpolicy"}}]}}}'
# 	needAv     = '{"query":{"bool":{"must":[{"match":{"companyRef.id":"{{companyId}}"}},{"match":{"isdeprecated":"false"}},{"exists":{"field":"security_reportcard.antiVirus"}},{"range":{"security_reportcard.antiVirus":{"gte":-1,"lt":5}}}]}}}'
# 	oldPc      = '{"query":{"bool":{"must":[{"match":{"companyRef.id":"{{companyId}}"}},{"match":{"object_type":"ad_computers"}},{"range":{"lastLogonTimestamp":{"lt":"now-90d"}}}]}}}'
# 	extScan    = '{"companyId":"{{companyId}}"}'
# }
# $reqFields = @{
# 	disk       = '["mountpoint","assetRef.name","total","free"]'
# 	passPolicy = '["complexityEnabled","lockoutDuration","lockoutObservationWindow","lockoutThreshold","maxPasswordAge","minPasswordAge","minPasswordLength","passwordHistoryCount","reversibleEncryptionEnabled","domain"]'
# 	needAv     = '["agentRef.name"]'
# 	oldPc      = '["name","host_name","lastLogonTimestamp"]'
# 	extScan    = '[""]'
# }

function Invoke-CyberCnsApi {
	param (
		[string]$Uri
	)

	$fullUri = $baseUri + $Uri + "?" + $Params
	try {
		$result = Invoke-WebRequest $fullUri -Method 'GET' -Headers $headers
		if ($result.total -gt $result.count) {
			$fullUri = $baseUri + $Uri + "?limit=" + $result.total + "&" + $Params
			$result = Invoke-WebRequest $fullUri -Method 'GET' -Headers $headers
		}
		return (ConvertFrom-Json $result.Content).data
        
	}
	catch {
		Write-Warning "Error running ""$FullUri"""
		throw $_
	}
}

function Invoke-Scan {
	param (
		[Parameter(Mandatory = $true)]
		[string]$Uri,
		[string]$CompanyId,
		[string]$Query,
		[string]$Skip = 0,
		[String]$Limit = 100,
		[String]$Sort,
		[array]$Fields
	)

	if ($Fields) {
		# $QuotedFields = $($Fields | ForEach-Object { "`"$_`"" }) -join ','
		# $QuotedFields = "[$QuotedFields]"
		$QuotedFields = $Fields
	}
	else {
		$QuotedFields = ""
	}
	if ($CompanyId) {
        
	}
    
	$params = "q=$Query&skip=$Skip&limit=$Limit&sort=$Sort&fields=$QuotedFields" -replace "{{companyId}}", $CompanyId

	#write-host $uri"/?"$params
	return Invoke-CyberCnsApi -Uri $Uri -Params $params 
}
 
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
Clear-Host
Write-Host "Getting company data..." -NoNewline

try {    
	$company = Invoke-WebRequest "$baseUri/api/company/" -Method 'GET' -Headers $headers -UseBasicParsing
	$statusCode = $company.StatusCode

	if ($statusCode -ne 200) {
		$log = New-Item "C:\Temp\CCNS_Reports\$(Get-Date -Format "yyyy-MM-dd-HH-mm")" -Force -Value $company.Content
		Write-Error "$baseURI responded with status code of $StatusCode. Please see $log"
	}
	else {
		Write-Host " Done!"
		## status code of 200, ask for which company to scan
        
		#? Convert JSON object to powershell object, get the data variable from it, select only name and _id, and sort by name
		$sorted = ($company.content | ConvertFrom-Json).data | Select-Object -Property name, _id | Sort-Object -Property name
        
		Write-Host "Select a company, then hit ""OK"""
		$Companies = $sorted | Out-GridView -PassThru -Title 'Pick a Company' #? PassThru lets you select an object from popup

		if ($null -eq $Companies) {
			Write-Host "No companies selected. Exiting..."
		}

		$Companies | ForEach-Object {
			## Company has been selected. Time to scan.

			$selectedCompany = $_
			Write-Host "Scanning $($selectedCompany.name)..."

			Write-Host "...	Disks " -NoNewline
			$disks = Invoke-Scan -Uri "/api/company/" -CompanyId $selectedCompany._id -Query $reqQueries.disk -Fields $reqFields.disk
			Write-Host "($($disks.count))"
			$null = $disks | Select-Object -excludeProperty "_id" | Out-GridView -Title "Disks for $($selectedCompany.name)" -PassThru

			Write-Host "...	Password Policy " -NoNewline
			$passPolicy = Invoke-Scan -Uri "/api/passwordpolicy/" -CompanyId $selectedCompany._id -Query $reqQueries.passPolicy -Fields $reqFields.passPolicy
			Write-Host "($($passPolicy.count))"
			$null = $passPolicy | Select-Object -excludeProperty "_id" | Out-GridView -Title "Password Policy for $($selectedCompany.name)" -PassThru

			Write-Host "...	Devices needing AV " -NoNewline
			$needAv = Invoke-Scan -Uri "/api/asset/" -CompanyId $selectedCompany._id -Query $reqQueries.needAv -Fields $reqFields.needAv
			Write-Host "($($needAv.count))"
			$null = $needAv | Select-Object -excludeProperty "_id" | Out-GridView -Title "Devices needing AV for $($selectedCompany.name)" -PassThru

			Write-Host "...	PCs over 90 days AD " -NoNewline
			$oldPc = Invoke-Scan -Uri "/api/adcomputers/" -CompanyId $selectedCompany._id -Query $reqQueries.oldPc -Fields $reqFields.oldPc
			Write-Host "($($oldPc.count))"
			$null = $oldPc | Select-Object -excludeProperty "_id" | Out-GridView -Title "PCs over 90 days AD for $($selectedCompany.name)" -PassThru
            
			Write-Host "...	External scan data " -NoNewline
			#TODO $extScan = Invoke-Scan -Uri "/api/externalscanportsinfo/" -CompanyId $selectedCompany._id -Query $reqQueries.extScan
			Write-Host "(coming soon...)"
			#TODO $null = $extScan | Select-Object -excludeProperty "_id" | Out-GridView -Title "External scan data for $($selectedCompany.name)" -PassThru

			Write-Host "Done!"
		}
	}
 
}
catch {
	Write-Host -ForegroundColor Red "`nError! Exception details: "
	$e = $_.Exception
	Write-Host -ForegroundColor Red ("`tMessage: " + $e.Message)
	Write-Host -ForegroundColor Red ("`tStatus code: " + $e.Response.StatusCode)
	Write-Host -ForegroundColor Red ("`tStatus description: " + $e.Response.StatusDescription)
	Write-Host -ForegroundColor Yellow ("Could be bad credentials. Run with -RenewCredentials to update")

}