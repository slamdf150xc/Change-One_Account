################################### GET-HELP #############################################
<#
.SYNOPSIS
    This script will initate CPM password change on each account that are a member of a group
    but not every for every member of the group.
    
.EXAMPLE
	./Change-One_Account.ps1
	./Change-One_Account.ps1 -CSV C:\temp\InventoryReports.InventoryReportUI_2019-05-16_155155.639.csv

.INPUTS
	CSV - The full path to the .csv exported from PVWA

.OUTPUTS
	None

.NOTES
	AUTHOR:
	Randy Brown

	VERSION HISTORY:
	1.0 05/17/2019 - Initial release
#>
######################### Parameters ####################################################
Param (
	[Parameter(Mandatory = $true)]
	[string] $CSV
)
######################### GLOBAL VARIABLE DECLARATIONS ###################################

$baseURI = "https://components.cyberarkdemo.com"		# URL or IP address for your environment
$appID = ""						# AppID created for resmuming users
$safe = ""						# Name of the safe that contains the CyberArk credential to resume the users
$object = ""						# The Object that corresponds to the credential in the Vault

########################## START FUNCTIONS ###############################################

function EPVLogin {
    param (
        $user,
        $pass
    )
	$data = @{
		username=$user
		password=$pass
		useRadiusAuthentication=$false
	}

	$loginData = $data | ConvertTo-Json

	try {
		Write-Host "Logging into EPV as $user..." -NoNewLine
		
		$ret = Invoke-RestMethod -Uri "$baseURI/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logon" -Method POST -Body $loginData -ContentType 'application/json'
		
		Write-Host "Success!" -ForegroundColor Green
	} catch {
		ErrorHandler "Login was not successful" $_.Exception.Message $_ $false
	}
	return $ret
}

function EPVLogoff {
	try {
		Write-Host "Logging off..." -NoNewline
		
		Invoke-RestMethod -Uri "$baseURI/PasswordVault/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logoff" -Method POST -Headers $header -ContentType 'application/json' | Out-Null
		
		Write-Host "Logged off!" -ForegroundColor Green
	} catch {
		ErrorHandler "Log off was not successful" $_.Exception.Message $_ $false
	}
}
function Get-APIAccount {
    try {
        Write-Host "Getting API account from the Vault..."
	
        Invoke-RestMethod -Uri "$baseURI/AIMWebService/api/Accounts?AppID=$appID&Safe=$safe&Object=$object" -Method GET -ContentType 'application/json' | Out-Null
        
        return $ret
    } catch {
        ErrorHandler "Get-APIAccount was not successful" $_.Exception.Message $_ $false
    }
}
function Get-Accounts {
    param (
        $acctName,
        $acctAddy
    )
    try {
        Write-Host "Searching for accounts..." -NoNewline

        $ret = Invoke-RestMethod -Uri "$baseURI/PasswordVault/api/Accounts?search=$acctName,%20$acctAddy" -Method Get -ContentType "application/json" -Headers $header

        Write-Host "Success!"-ForegroundColor Green

        return $ret.value.ID
    }
    catch {
        ErrorHandler "Get-Accounts was not successful" $_.Exception.Message $_ $true
    }
}
function ChangeCredential {
    param (
        $acctName,
        $acctID
    )
    $data = @{
        ChangeEntireGroup=$false
    }
    $body = $data | ConvertTo-Json

    try {
        Write-Host "Changing credential for $acctName..." -NoNewline

        Invoke-RestMethod -Uri "$baseURI/PasswordVault/API/Accounts/$acctID/Change" -Method Post -Body $body -ContentType "application/json" -Headers $header | Out-Null

        Write-Host "Success!" -ForegroundColor Green
    }
    catch {
        ErrorHandler "ChangeCredential was not successful" $_.Exception.Message $_ $true
    }
}
function ErrorHandler {
    param (
        $message,
        $exceptionMessage,
        $fullMessage,
        $logoff
    )
    Write-Host "---------- Error ----------"    
	Write-Host $message -ForegroundColor Red
	Write-Host "Exception Message:"
	Write-Host $exceptionMessage -ForegroundColor Red
	Write-Host "Full Error Message:"
	Write-Host $fullMessage -ForegroundColor Red
    Write-Host "Stopping script" -ForegroundColor Yellow
    Write-Host "-------- End Error --------"    
	
	If ($logoff) {
		EPVLogoff
	}
	Exit 1
}

########################## END FUNCTIONS #################################################

########################## MAIN SCRIPT BLOCK #############################################

### Uncomment if using CCP ###
<#
$cred = Get-APIAccount
$user = $cred.UserName
$login = EPVLogin $cred.UserName $cred.Content
#>

### Comment if using CCP ###
Write-Host "Please log into EPV"
$user = Read-Host "EPV User Name"
$securePassword = Read-Host "Password" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$unsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$login = EPVLogin $user $unsecurePassword
$unsecurePassword = ""

$script:header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$script:header.Add("Authorization", $login.CyberArkLogonResult)

$accounts = Import-Csv -Path $CSV

Write-Host ""

foreach ($a in $accounts) {
    Write-Host "---------------------"
    $acctName = $a."Target system user name"
    $acctAddy = $a."Target system address"

    #ChangeCredential -acctName $acctName -acctID (Get-Accounts -acctName $acctName -acctAddy $acctAddy)
    $accountNames =  Get-Accounts -acctName $acctName -acctAddy $acctAddy

    Write-Host "$accountNames"
}

Write-Host "---------------------"
EPVLogoff

########################### END SCRIPT ###################################################