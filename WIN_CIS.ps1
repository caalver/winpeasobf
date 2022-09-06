#WINDOWS SID CONSTANTS
#https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers

$SID_NOONE = "`"`""
$SID_ADMINISTRATORS = "*S-1-5-32-544"
$SID_GUESTS = "*S-1-5-32-546"
$SID_SERVICE = "*S-1-5-6"
$SID_NETWORK_SERVICE = "*S-1-5-20"
$SID_LOCAL_SERVICE = "*S-1-5-19"
$SID_LOCAL_ACCOUNT = "*S-1-5-113"
$SID_WINDOW_MANAGER_GROUP = "*S-1-5-90-0"
$SID_REMOTE_DESKTOP_USERS = "*S-1-5-32-555"
$SID_VIRTUAL_MACHINE = "*S-1-5-83-0"
$SID_AUTHENTICATED_USERS = "*S-1-5-11"
$SID_WDI_SYSTEM_SERVICE = "*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"
$SID_BACKUP_OPERATORS = "S-1-5-32-551"

function Write-Info($text) {
    Write-Host $text -ForegroundColor Yellow
}

function Write-Testing($text) {
    Write-Host $text -ForegroundColor Cyan
}

function Write-Fail($text) {
    Write-Host $text -ForegroundColor Red
}

function Write-Pass($text) {
    Write-Host $text -ForegroundColor Green
}

Write-Info "---------------------------------------------------"
Write-Info "   CIS Microsoft Windows Server 2019 Benchmark"
Write-Info "               Written by kotsios"
Write-Info "---------------------------------------------------"
Write-Info ""
Write-Info "---------------------------------------------------"
Write-Info "            Retrieving information"
Write-Info "---------------------------------------------------"
secedit /export /cfg ${env:appdata}\secpol.cfg
Write-Info "---------------------------------------------------"
Write-Info "                      START"
Write-Info "---------------------------------------------------"
Write-Info "            Section: 1 Account Policies"
Write-Info "---------------------------------------------------"
Write-Info "            Section: 1.1 Password Policy"
Write-Info "---------------------------------------------------"

#1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)' (Scored)
Write-Testing "TESTING: 1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)' (Scored)"
Write-Output ( net accounts | Select-String -SimpleMatch 'Length of password history maintained' )
$out_1_1_1 = Write-Output ( net accounts | Select-String -SimpleMatch 'Length of password history maintained')
$str = $out_1_1_1 -replace '\s+', '' -split ':' | Select -Index 1

if ( $out_1_1_1 -like '*None*' )
{
	Write-Fail "FAIL: 1.1.1"
}
elseif ( $str -gt 23 )
{
	Write-Pass "PASS: 1.1.1"
}
else
{
	Write-Fail "FAIL: 1.1.1"
}

#1.1.2 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0' (Scored)
Write-Testing "TESTING: 1.1.2 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0' (Scored)"
Write-Output ( net accounts | Select-String -SimpleMatch 'Maximum password age' )
$out_1_1_2 = Write-Output ( net accounts | Select-String -SimpleMatch 'Maximum password age' )
$str = $out_1_1_2 -replace '\s+', '' -split ':' | Select -Index 1
if ( $out_1_1_2 -like '*None*' )
{
	Write-Fail "FAIL: 1.1.2"
}
elseif ( $str -lt 61 )
{
	Write-Pass "PASS: 1.1.2"
}
else
{
	Write-Fail "FAIL: 1.1.2"
}

#1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)' (Scored)
Write-Testing "TESTING: 1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)' (Scored)"
Write-Output (net accounts | Select-String -SimpleMatch 'Minimum password age' )
$out_1_1_3 = Write-Output (net accounts | Select-String -SimpleMatch 'Minimum password age' )
$str = $out_1_1_3 -replace '\s+', '' -split ':' | Select -Index 1
if ( $out_1_1_3 -like '*None*' )
{
	Write-Fail "FAIL: 1.1.3"
}
elseif ( $str -gt 0 )
{
	Write-Pass "PASS: 1.1.3"
}
else
{
	Write-Fail "FAIL: 1.1.3"
}

#1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)' (Scored)
Write-Testing "TESTING: 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)' (Scored)"
Write-Output ( net accounts | Select-String -SimpleMatch 'Minimum password length')
$out_1_1_4 = Write-Output ( net accounts | Select-String -SimpleMatch 'Minimum password length')
$str = $out_1_1_4 -replace '\s+', '' -split ':' | Select -Index 1
if ( $out_1_1_4 -like '*None*' )
{
	Write-Fail "FAIL: 1.1.4"
}
elseif ( $str -gt 13 )
{
	Write-Pass "PASS: 1.1.4"
}
else
{
	Write-Fail "FAIL: 1.1.4"
}

#1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled' (Scored)
Write-Testing "TESTING: 1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled' (Scored)"
#secedit /export /cfg ${env:appdata}\secpol.cfg
#Get-Content ${env:appdata}\secpol.cfg
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'PasswordComplexity')
$out_1_1_5 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'PasswordComplexity')
$str = $out_1_1_5 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq 0 )
{
	Write-Fail "FAIL: 1.1.5"
}
else
{
	Write-Pass "PASS: 1.1.5"
}

#1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled' (Scored)
Write-Testing "TESTING: 1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled' (Scored)"
#secedit /export /cfg ${env:appdata}\secpol.cfg
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'ClearTextPassword')
$out_1_1_6 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'ClearTextPassword')
$str = $out_1_1_6 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq 0 )
{
	Write-Pass "PASS: 1.1.6"
}
else
{
	Write-Fail "FAIL: 1.1.6"
}
Write-Info "---------------------------------------------------"
Write-Info "           Section: 1.2 Account Lockout Policy"
Write-Info "---------------------------------------------------"

#1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)' (Scored)
Write-Testing "TESTING: 1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)' (Scored)"
Write-Output ( net accounts | Select-String -SimpleMatch 'lockout duration')
$out_1_2_1 = Write-Output ( net accounts | Select-String -SimpleMatch 'lockout duration')
$str = $out_1_2_1 -replace '\s+', '' -split ':' | Select -Index 1
if ( $out_1_2_1 -like '*Never*' )
{
	Write-Fail "FAIL: 1.2.1"
}
elseif ( $str -gt 14 )
{
	Write-Pass "PASS: 1.2.1"
}
else
{
	Write-Fail "FAIL: 1.2.1"
}

#1.2.2 (L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0' (Scored)
Write-Testing "TESTING: 1.2.2 (L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0' (Scored)"
Write-Output ( net accounts | Select-String -SimpleMatch 'lockout threshold' )
$out_1_2_2 = Write-Output ( net accounts | Select-String -SimpleMatch 'lockout threshold' )
$str = $out_1_2_2 -replace '\s+', '' -split ':' | Select -Index 1
if ( $out_1_2_2 -like '*Never*' )
{
	Write-Fail "FAIL: 1.2.2"
}
elseif ( $str -lt 11 )
{
	Write-Pass "PASS: 1.2.2"
}
else
{
	Write-Fail "FAIL: 1.2.2"
}

# 1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)' (Scored)
Write-Testing "TESTING: 1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)' (Scored)"
Write-Output ( net accounts | Select-String -SimpleMatch 'Lockout observation window' )
$out_1_2_3 = Write-Output ( net accounts | Select-String -SimpleMatch 'Lockout observation window' )
$str = $out_1_2_3 -replace '\s+', '' -split ':' | Select -Index 1
if ( $out_1_2_3 -like '*Never*' )
{
	Write-Fail "FAIL: 1.2.3"
}
elseif ( $str -gt 14 )
{
	Write-Pass "PASS: 1.2.3"
}
else
{
	Write-Fail "FAIL: 1.2.3"
}
Write-Info "---------------------------------------------------"
Write-Info "              Section: 2 Local Policies"
Write-Info "---------------------------------------------------"
Write-Info "           Section: 2.2 User Rights Assignment"
Write-Info "---------------------------------------------------"
#2.2.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Access Credential Manager as a trusted caller
Write-Testing "TESTING: 2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One' (Scored)"
#SetUserRight "SeTrustedCredManAccessPrivilege" ($SID_NOONE)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeTrustedCredManAccessPrivilege')
$out_2_2_1 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeTrustedCredManAccessPrivilege')
if ($out_2_2_1 -eq $null)
{
	Write-Fail "FAIL: 2.2.1 (NULL)"
}
else
{
	$str = $out_2_2_1 -replace '\s+', '' -split '=' | Select -Index 1
	[regex]$regex = ','
	$count = $regex.matches($str).count
	$condition = 1
	for ($num = 0; $num -le ($count); $num++)
	{
		$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
		if ($sid -ne $SID_NOONE)
		{
			$condition = 0
		}
	}
	if ($condition -eq 0)
	{
		Write-Fail "FAIL: 2.2.1"
	}
	else
	{
		Write-Pass "Pass: 2.2.1"
	}
}

#2.2.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Access this computer from the network
Write-Testing "TESTING: 2.2.3 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users"
#SetUserRight "SeNetworkLogonRight" ($SID_ADMINISTRATORS, $SID_AUTHENTICATED_USERS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeNetworkLogonRight')
$out_2_2_3 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeNetworkLogonRight')
if ($out_2_2_3 -eq $null)
{
	Write-FAIL "FAIL: 2.2.3 (NULL)"
}
else
{
	$str = $out_2_2_3 -replace '\s+', '' -split '=' | Select -Index 1
	[regex]$regex = ','
	$count = $regex.matches($str).count
	$condition = 1
	for ($num = 0; $num -le ($count); $num++)
	{
		$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
		if (($sid -ne $SID_ADMINISTRATORS) -and ($sid -ne $SID_AUTHENTICATED_USERS))
		{
			$condition = 0
		}
	}
	if (($condition -eq 0) -or ($count -gt 1))
	{
		Write-Fail "FAIL: 2.2.3"
	}
	else
	{
		Write-Pass "Pass: 2.2.3"
	}
}

#2.2.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Act as part of the operating system
Write-Testing "TESTING: 2.2.4 (L1) Ensure 'Act as part of the operating system' is set to 'No One' (Scored)"
#SetUserRight "SeTcbPrivilege" ($SID_NOONE)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeTcbPrivilege')
$out_2_2_4 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeTcbPrivilege')
if ($out_2_2_4 -eq $null)
{
	Write-Fail "FAIL: 2.2.4 (NULL)"
}
else
{
	$str = $out_2_2_4 -replace '\s+', '' -split '=' | Select -Index 1
	[regex]$regex = ','
	$count = $regex.matches($str).count
	$condition = 1
	for ($num = 0; $num -le ($count); $num++)
	{
		$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
		if ($sid -ne $SID_NOONE)
		{
			$condition = 0
		}
	}
	if ($condition -eq 0)
	{
		Write-Fail "FAIL: 2.2.4"
	}
	else
	{
		Write-Pass "Pass: 2.2.4"
	}
}

#2.2.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Adjust memory quotas for a process
Write-Testing "TESTING: 2.2.6 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE"
#SetUserRight "SeIncreaseQuotaPrivilege" ($SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE, $SID_ADMINISTRATORS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeIncreaseQuotaPrivilege')
$out_2_2_6 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeIncreaseQuotaPrivilege')
if ($out_2_2_6 -eq $null)
{
	Write-Fail "FAIL: 2.2.6 (NULL)"
}
else
	{
	$str = $out_2_2_6 -replace '\s+', '' -split '=' | Select -Index 1
	[regex]$regex = ','
	$count = $regex.matches($str).count
	$condition = 1
	for ($num = 0; $num -le ($count); $num++)
	{
		$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
		if (($sid -ne $SID_ADMINISTRATORS) -and ($sid -ne $SID_LOCAL_SERVICE) -and ($sid -ne $SID_NETWORK_SERVICE))
		{
			$condition = 0
		}
	}
	if (($condition -eq 0) -or ($count -gt 2))
	{
		Write-Fail "FAIL: 2.2.6"
	}
	else
	{
		Write-Pass "Pass: 2.2.6"
	}
}

#2.2.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Allow log on locally
Write-Testing "TESTING: 2.2.7 (L1) Ensure 'Allow log on locally' is set to 'Administrators'"
#SetUserRight "SeInteractiveLogonRight" (,$SID_ADMINISTRATORS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeInteractiveLogonRight')
$out_2_2_7 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeInteractiveLogonRight')
if ($out_2_2_7 -eq $null)
{
	Write-Fail "FAIL: 2.2.7 (NULL)"
}
else
{
	$str = $out_2_2_7 -replace '\s+', '' -split '=' | Select -Index 1
	[regex]$regex = ','
	$count = $regex.matches($str).count
	$condition = 1
	for ($num = 0; $num -le ($count); $num++)
	{
		$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
		if ($sid -ne $SID_ADMINISTRATORS)
		{
			$condition = 0
		}
	}
	if ($condition -eq 0)
	{
		Write-Fail "FAIL: 2.2.7"
	}
	else
	{
		Write-Pass "Pass: 2.2.7"
	}
}

#2.2.9 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Allow log on through Remote Desktop Services
Write-Testing "TESTING: 2.2.9 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'"
#SetUserRight "SeRemoteInteractiveLogonRight" ($SID_ADMINISTRATORS, $SID_REMOTE_DESKTOP_USERS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRemoteInteractiveLogonRight')
$out_2_2_9 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRemoteInteractiveLogonRight')
if ($out_2_2_9 -eq $null)
{
	Write-Fail "FAIL: 2.2.9 (NULL)"
}
else
{
	$str = $out_2_2_9 -replace '\s+', '' -split '=' | Select -Index 1
	[regex]$regex = ','
	$count = $regex.matches($str).count
	$condition = 1
	for ($num = 0; $num -le ($count); $num++)
	{
		$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
		if (($sid -ne $SID_ADMINISTRATORS) -and ($sid -ne $SID_REMOTE_DESKTOP_USERS))
		{
			$condition = 0
		}
	}
	if (($condition -eq 0) -or ($count -gt 1))
	{
		Write-Fail "FAIL: 2.2.9"
	}
	else
	{
		Write-Pass "Pass: 2.2.9"
	}
}

#2.2.10 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Back up files and directories
Write-Testing "TESTING: 2.2.10 (L1) Ensure 'Back up files and directories' is set to 'Administrators'"
#SetUserRight "SeBackupPrivilege" (,$SID_ADMINISTRATORS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeBackupPrivilege')
$out_2_2_10 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeBackupPrivilege')
if ($out_2_2_10 -eq $null)
{
	Write-Fail "FAIL: 2.2.10 (NULL)"
}
else
{
$str = $out_2_2_10 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if ($sid -ne $SID_ADMINISTRATORS)
	{
		$condition = 0
	}
}
if ($condition -eq 0)
{
	Write-Fail "FAIL: 2.2.10"
}
else
{
	Write-Pass "Pass: 2.2.10"
}
}
#2.2.11 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Change the system time
Write-Testing "TESTING: 2.2.11 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
#SetUserRight "SeSystemtimePrivilege" ($SID_ADMINISTRATORS,$SID_LOCAL_SERVICE)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSystemtimePrivilege')
$out_2_2_11 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSystemtimePrivilege')
if ($out_2_2_11 -eq $null)
{
	Write-Fail "FAIL: 2.2.11 (NULL)"
}
else
{
$str = $out_2_2_11 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num

	if (($sid -ne $SID_ADMINISTRATORS) -and ($sid -ne $SID_LOCAL_SERVICE))
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -gt 1))
{
	Write-Fail "FAIL: 2.2.11"
}
else
{
	Write-Pass "Pass: 2.2.11"
}
}
#2.2.12 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Change the time zone
Write-Testing "TESTING: 2.2.12 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"
#SetUserRight "SeTimeZonePrivilege" ($SID_LOCAL_SERVICE,$SID_ADMINISTRATORS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeTimeZonePrivilege')
$out_2_2_12 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeTimeZonePrivilege')
if ($out_2_2_12 -eq $null)
{
	Write-Fail "FAIL: 2.2.12 (NULL)"
}
else
{
$str = $out_2_2_12 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if (($sid -ne $SID_ADMINISTRATORS) -and ($sid -ne $SID_LOCAL_SERVICE))
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -gt 1))
{
	Write-Fail "FAIL: 2.2.12"
}
else
{
	Write-Pass "Pass: 2.2.12"
}
}
#2.2.13 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create a pagefile
Write-Testing "TESTING: 2.2.13 (L1) Ensure 'Create a pagefile' is set to 'Administrators'"
#SetUserRight "SeCreatePagefilePrivilege" (,$SID_ADMINISTRATORS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreatePagefilePrivilege')
$out_2_2_13 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreatePagefilePrivilege')
if ($out_2_2_13 -eq $null)
{
	Write-Fail "FAIL: 2.2.13 (NULL)"
}
else
{
$str = $out_2_2_13 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if ($sid -ne $SID_ADMINISTRATORS)
	{
		$condition = 0
	}
}
if ($condition -eq 0)
{
	Write-Fail "FAIL: 2.2.13"
}
else
{
	Write-Pass "Pass: 2.2.13"
}
}
#2.2.14 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create a token object
Write-Testing "TESTING: 2.2.14 (L1) Ensure 'Create a token object' is set to 'No One'"
#SetUserRight "SeCreateTokenPrivilege" (,$SID_NOONE)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreateTokenPrivilege')
$out_2_2_14 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreateTokenPrivilege')
if ($out_2_2_14 -eq $null)
{
	Write-Fail "FAIL: 2.2.14 (NULL)"
}
else
{
	$str = $out_2_2_14 -replace '\s+', '' -split '=' | Select -Index 1
	[regex]$regex = ','
	$count = $regex.matches($str).count
	$condition = 1
	for ($num = 0; $num -le ($count); $num++)
	{
		$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
		if ($sid -ne $SID_NOONE)
		{
			$condition = 0
		}
	}
	if ($condition -eq 0)
	{
		Write-Fail "FAIL: 2.2.14"
	}
	else
	{
		Write-Pass "Pass: 2.2.14"
	}
}

#2.2.15 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create global objects
Write-Testing "TESTING: 2.2.15 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
#SetUserRight "SeCreateGlobalPrivilege" ($SID_ADMINISTRATORS,$SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE,$SID_SERVICE)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreateGlobalPrivilege')
$out_2_2_15 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreateGlobalPrivilege')
if ($out_2_2_15 -eq $null)
{
	Write-Fail "FAIL: 2.2.15 (NULL)"
}
else
{
$str = $out_2_2_15 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if (($sid -ne $SID_ADMINISTRATORS) -and ($sid -ne $SID_LOCAL_SERVICE) -and ($sid -ne $SID_NETWORK_SERVICE) -and ($sid -ne $SID_SERVICE))
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -gt 3))
{
	Write-Fail "FAIL: 2.2.15"
}
else
{
	Write-Pass "Pass: 2.2.15"
}
}
#2.2.16 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create permanent shared objects
Write-Testing "TESTING: 2.2.16 (L1) Ensure 'Create permanent shared objects' is set to 'No One'"
#SetUserRight "SeCreatePermanentPrivilege" (,$SID_NOONE)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreatePermanentPrivilege')
$out_2_2_16 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreatePermanentPrivilege')
if ($out_2_2_16 -eq $null)
{
	Write-Fail "FAIL: 2.2.16 (NULL)"
}
else
{
	$str = $out_2_2_16 -replace '\s+', '' -split '=' | Select -Index 1
	[regex]$regex = ','
	$count = $regex.matches($str).count
	$condition = 1
	for ($num = 0; $num -le ($count); $num++)
	{
		$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
		if ($sid -ne $SID_NOONE)
		{
			$condition = 0
		}
	}
	if ($condition -eq 0)
	{
		Write-Fail "FAIL: 2.2.16"
	}
	else
	{
		Write-Pass "Pass: 2.2.16"
	}
}

#2.2.18 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create symbolic links
Write-Testing "TESTING: 2.2.18 (L1) Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'"
#SetUserRight "SeCreateSymbolicLinkPrivilege" ($SID_ADMINISTRATORS,$SID_VIRTUAL_MACHINE)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreateSymbolicLinkPrivilege')
$out_2_2_18 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeCreateSymbolicLinkPrivilege')
if ($out_2_2_18 -eq $null)
{
	Write-Fail "FAIL: 2.2.18 (NULL)"
}
else
{
$str = $out_2_2_18 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if (($sid -ne $SID_ADMINISTRATORS) -and ($sid -ne $SID_VIRTUAL_MACHINE))
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -lt 1))
{
	Write-Fail "FAIL: 2.2.18"
}
else
{
	Write-Pass "Pass: 2.2.18"
}
}
#2.2.19 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Debug programs
Write-Testing "TESTING: 2.2.19 (L1) Ensure 'Debug programs' is set to 'Administrators'"
#SetUserRight "SeDebugPrivilege" (,$SID_ADMINISTRATORS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDebugPrivilege')
$out_2_2_19 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDebugPrivilege')
if ($out_2_2_19 -eq $null)
{
	Write-Fail "FAIL: 2.2.19 (NULL)"
}
else
{
$str = $out_2_2_19 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if ($sid -ne $SID_ADMINISTRATORS)
	{
		$condition = 0
	}
}
if ($condition -eq 0)
{
	Write-Fail "FAIL: 2.2.19"
}
else
{
	Write-Pass "Pass: 2.2.19"
}
}
#2.2.21 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny access to this computer from the network
Write-Testing "TESTING: 2.2.21 (L1) Ensure 'Deny access to this computer from the network' to include 'Guests, Local account and member of Administrators group'"
#SetUserRight "SeDenyNetworkLogonRight" ($SID_LOCAL_ACCOUNT, $($AdminNewAccountName),$($SID_GUESTS))
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyNetworkLogonRight')
$out_2_2_21 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyNetworkLogonRight')
if ($out_2_2_21 -eq $null)
{
	Write-Fail "FAIL: 2.2.21 (NULL)"
}
else
{
$str = $out_2_2_21 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if (($sid -ne $SID_GUESTS) -and ($sid -NotLike '*Guest*') -and ($sid -ne $SID_LOCAL_ACCOUNT))
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -lt 1))
{
	Write-Fail "FAIL: 2.2.21"
}
else
{
	Write-Pass "Pass: 2.2.21"
}
}
#2.2.22 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on as a batch job
Write-Testing "TESTING: 2.2.22 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'"
#SetUserRight "SeDenyBatchLogonRight" (,$SID_GUESTS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyBatchLogonRight')
$out_2_2_22 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyBatchLogonRight')
if ($out_2_2_22 -eq $null)
{
	Write-Fail "FAIL: 2.2.22 (NULL)"
}
else
{
	$str = $out_2_2_22 -replace '\s+', '' -split '=' | Select -Index 1
	[regex]$regex = ','
	$count = $regex.matches($str).count
	$condition = 1
	for ($num = 0; $num -le ($count); $num++)
	{
		$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
		if (($sid -ne $SID_GUESTS) -and ($sid -NotLike '*Guest*'))
		{
			$condition = 0
		}
	}
	if ($condition -eq 0)
	{
		Write-Fail "FAIL: 2.2.22"
	}
	else
	{
		Write-Pass "Pass: 2.2.22"
	}
}

#2.2.23 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on as a service
Write-Testing "TESTING: 2.2.23 (L1) Ensure 'Deny log on as a service' to include 'Guests'"
#SetUserRight "SeDenyServiceLogonRight" (,$SID_GUESTS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyServiceLogonRight')
$out_2_2_23 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyServiceLogonRight')
if ($out_2_2_23 -eq $null)
{
	Write-Fail "FAIL: 2.2.23 (NULL)"
}
else
{
	$str = $out_2_2_23 -replace '\s+', '' -split '=' | Select -Index 1
	[regex]$regex = ','
	$count = $regex.matches($str).count
	$condition = 1
	for ($num = 0; $num -le ($count); $num++)
	{
		$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
		if (($sid -ne $SID_GUESTS) -and ($sid -NotLike '*Guest*'))
		{
			$condition = 0
		}
	}
	if ($condition -eq 0)
	{
		Write-Fail "FAIL: 2.2.23"
	}
	else
	{
		Write-Pass "Pass: 2.2.23"
	}
}

#2.2.24 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on locally
Write-Testing "TESTING: 2.2.24 (L1) Ensure 'Deny log on locally' to include 'Guests'"
#SetUserRight "SeDenyInteractiveLogonRight" (,$SID_GUESTS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyInteractiveLogonRight')
$out_2_2_24 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyInteractiveLogonRight')
if ($out_2_2_24 -eq $null)
{
	Write-Fail "FAIL: 2.2.24 (NULL)"
}
else
{
$str = $out_2_2_24 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if (($sid -ne $SID_GUESTS) -and ($sid -NotLike '*Guest*'))
	{
		$condition = 0
	}
}
if ($condition -eq 0)
{
	Write-Fail "FAIL: 2.2.24"
}
else
{
	Write-Pass "Pass: 2.2.24"
}
}
#2.2.26 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on through Remote Desktop Services
Write-Testing "TESTING: 2.2.26 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account'"
#SetUserRight "SeDenyRemoteInteractiveLogonRight" ($SID_LOCAL_ACCOUNT, $GuestNewAccountName)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyRemoteInteractiveLogonRight')
$out_2_2_26 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDenyRemoteInteractiveLogonRight')
if ($out_2_2_26 -eq $null)
{
	Write-Fail "FAIL: 2.2.26 (NULL)"
}
else
{
	$str = $out_2_2_26 -replace '\s+', '' -split '=' | Select -Index 1
	[regex]$regex = ','
	$count = $regex.matches($str).count
	$condition = 1
	for ($num = 0; $num -le ($count); $num++)
	{
		$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
		if (($sid -ne $SID_GUESTS) -and ($sid -NotLike '*Guest*') -and ($sid -ne $SID_LOCAL_ACCOUNT))
		{
			$condition = 0
		}
	}
	if (($condition -eq 0) -or ($count -lt 1))
	{
		Write-Fail "FAIL: 2.2.26"
	}
	else
	{
		Write-Pass "Pass: 2.2.26"
	}
}

#2.2.28 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Enable computer and user accounts to be trusted for delegation
Write-Testing "TESTING: 2.2.28 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'"
#SetUserRight "SeDelegateSessionUserImpersonatePrivilege" (,$SID_NOONE)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDelegateSessionUserImpersonatePrivilege')
$out_2_2_28 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeDelegateSessionUserImpersonatePrivilege')
if ($out_2_2_28 -eq $null)
{
	Write-Fail "FAIL: 2.2.28 (NULL)"
}
else
{
$str = $out_2_2_28 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if ($sid -ne $SID_NOONE)
	{
		$condition = 0
	}
}
if ($condition -eq 0)
{
	Write-Fail "FAIL: 2.2.28"
}
else
{
	Write-Pass "Pass: 2.2.28"
}
}
#2.2.29 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Force shutdown from a remote system
Write-Testing "TESTING: 2.2.29 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
#SetUserRight "SeRemoteShutdownPrivilege" (,$SID_ADMINISTRATORS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRemoteShutdownPrivilege')
$out_2_2_29 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRemoteShutdownPrivilege')
if ($out_2_2_29 -eq $null)
{
	Write-Fail "FAIL: 2.2.29 (NULL)"
}
else
{
$str = $out_2_2_29 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if ($sid -ne $SID_ADMINISTRATORS)
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -gt 0))
{
	Write-Fail "FAIL: 2.2.29"
}
else
{
	Write-Pass "Pass: 2.2.29"
}
}
#2.2.30 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Generate security audits
Write-Testing "TESTING: 2.2.30 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE' (Scored)"
#SetUserRight "SeAuditPrivilege" ($SID_LOCAL_SERVICE,$SID_NETWORK_SERVICE)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeAuditPrivilege')
$out_2_2_30 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeAuditPrivilege')
if ($out_2_2_30 -eq $null)
{
	Write-Fail "FAIL: 2.2.30 (NULL)"
}
else
{
$str = $out_2_2_30 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if (($sid -ne $SID_LOCAL_SERVICE) -and ($sid -ne $SID_NETWORK_SERVICE))
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -gt 1))
{
	Write-Fail "FAIL: 2.2.30"
}
else
{
	Write-Pass "Pass: 2.2.30"
}
}
#2.2.32 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Impersonate a client after authentication
Write-Testing "TESTING: 2.2.32 Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE, IIS_IUSRS'"
#SetUserRight "SeImpersonatePrivilege" ($SID_LOCAL_SERVICE,$SID_NETWORK_SERVICE,$SID_ADMINISTRATORS,$SID_SERVICE)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeImpersonatePrivilege')
$out_2_2_32 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeImpersonatePrivilege')
if ($out_2_2_32 -eq $null)
{
	Write-Fail "FAIL: 2.2.32 (NULL)"
}
else
{
$str = $out_2_2_32 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if (($sid -ne $SID_LOCAL_SERVICE) -and ($sid -ne $SID_NETWORK_SERVICE) -and ($sid -ne $SID_ADMINISTRATORS) -and ($sid -ne $SID_SERVICE))
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -lt 3))
{
	Write-Fail "FAIL: 2.2.32"
}
else
{
	Write-Pass "Pass: 2.2.32"
}
}
#2.2.33 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Increase scheduling priority
Write-Testing "TESTING: 2.2.33 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'"
#SetUserRight "SeIncreaseBasePriorityPrivilege" ($SID_ADMINISTRATORS,$SID_WINDOW_MANAGER_GROUP)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeIncreaseBasePriorityPrivilege')
$out_2_2_33 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeIncreaseBasePriorityPrivilege')
if ($out_2_2_33 -eq $null)
{
	Write-Fail "FAIL: 2.2.33 (NULL)"
}
else
{
$str = $out_2_2_33 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if (($sid -ne $SID_ADMINISTRATORS) -and ($sid -ne $SID_WINDOW_MANAGER_GROUP))
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -gt 1))
{
	Write-Fail "FAIL: 2.2.33"
}
else
{
	Write-Pass "Pass: 2.2.33"
}
}
#2.2.34 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Load and unload device drivers
Write-Testing "TESTING: 2.2.34 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'"
#SetUserRight "SeLoadDriverPrivilege" (,$SID_ADMINISTRATORS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeLoadDriverPrivilege')
$out_2_2_34 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeLoadDriverPrivilege')
if ($out_2_2_34 -eq $null)
{
	Write-Fail "FAIL: 2.2.34 (NULL)"
}
else
{
$str = $out_2_2_34 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if ($sid -ne $SID_ADMINISTRATORS)
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -gt 0))
{
	Write-Fail "FAIL: 2.2.34"
}
else
{
	Write-Pass "Pass: 2.2.34"
}
}
#2.2.35 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Lock pages in memory
Write-Testing "TESTING: 2.2.35 (L1) Ensure 'Lock pages in memory' is set to 'No One'"
#SetUserRight "SeLockMemoryPrivilege" (,$SID_NOONE)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeLockMemoryPrivilege')
$out_2_2_35 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeLockMemoryPrivilege')
if ($out_2_2_35 -eq $null)
{
	Write-Fail "FAIL: 2.2.35 (NULL)"
}
else
{
	$str = $out_2_2_35 -replace '\s+', '' -split '=' | Select -Index 1
	[regex]$regex = ','
	$count = $regex.matches($str).count
	$condition = 1
	for ($num = 0; $num -le ($count); $num++)
	{
		$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
		if ($sid -ne $SID_NOONE)
		{
			$condition = 0
		}
	}
	if ($condition -eq 0)
	{
		Write-Fail "FAIL: 2.2.35"
	}
	else
	{
		Write-Pass "Pass: 2.2.35"
	}
}

#2.2.38 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Manage auditing and security log
Write-Testing "TESTING: 2.2.38 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators'"
#SetUserRight "SeSecurityPrivilege" (,$SID_ADMINISTRATORS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSecurityPrivilege')
$out_2_2_38 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSecurityPrivilege')
if ($out_2_2_38 -eq $null)
{
	Write-Fail "FAIL: 2.2.38 (NULL)"
}
else
{
$str = $out_2_2_38 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if ($sid -ne $SID_ADMINISTRATORS)
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -gt 0))
{
	Write-Fail "FAIL: 2.2.38"
}
else
{
	Write-Pass "Pass: 2.2.38"
}
}
#2.2.39 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Modify an object label
Write-Testing "TESTING: 2.2.39 (L1) Ensure 'Modify an object label' is set to 'No One'"
#SetUserRight "SeRelabelPrivilege" (,$SID_NOONE)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRelabelPrivilege')
$out_2_2_39 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRelabelPrivilege')
if ($out_2_2_39 -eq $null)
{
	Write-Fail "FAIL: 2.2.39 (NULL)"
}
else
{
	$str = $out_2_2_39 -replace '\s+', '' -split '=' | Select -Index 1
	[regex]$regex = ','
	$count = $regex.matches($str).count
	$condition = 1
	for ($num = 0; $num -le ($count); $num++)
	{
		$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
		if ($sid -ne $SID_NOONE)
		{
			$condition = 0
		}
	}
	if ($condition -eq 0)
	{
		Write-Fail "FAIL: 2.2.39"
	}
	else
	{
		Write-Pass "Pass: 2.2.39"
	}
}

#2.2.40 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Modify firmware environment values
Write-Testing "TESTING: 2.2.40 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'"
#SetUserRight "SeSystemEnvironmentPrivilege" (,$SID_ADMINISTRATORS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSystemEnvironmentPrivilege')
$out_2_2_40 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSystemEnvironmentPrivilege')
if ($out_2_2_40 -eq $null)
{
	Write-Fail "FAIL: 2.2.40 (NULL)"
}
else
{
$str = $out_2_2_40 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if ($sid -ne $SID_ADMINISTRATORS)
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -gt 0))
{
	Write-Fail "FAIL: 2.2.40"
}
else
{
	Write-Pass "Pass: 2.2.40"
}
}
#2.2.41 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Perform volume maintenance tasks
Write-Testing "TESTING: 2.2.41 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
#SetUserRight "SeManageVolumePrivilege" (,$SID_ADMINISTRATORS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeManageVolumePrivilege')
$out_2_2_41 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeManageVolumePrivilege')
if ($out_2_2_41 -eq $null)
{
	Write-Fail "FAIL: 2.2.41 (NULL)"
}
else
{
$str = $out_2_2_41 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if ($sid -ne $SID_ADMINISTRATORS)
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -gt 0))
{
	Write-Fail "FAIL: 2.2.41"
}
else
{
	Write-Pass "Pass: 2.2.41"
}
}
#2.2.42 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Profile single process
Write-Testing "TESTING: 2.2.42 (L1) Ensure 'Profile single process' is set to 'Administrators'"
#SetUserRight "SeProfileSingleProcessPrivilege" (,$SID_ADMINISTRATORS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeProfileSingleProcessPrivilege')
$out_2_2_42 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeProfileSingleProcessPrivilege')
if ($out_2_2_42 -eq $null)
{
	Write-Fail "FAIL: 2.2.42 (NULL)"
}
else
{
$str = $out_2_2_42 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if ($sid -ne $SID_ADMINISTRATORS)
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -gt 0))
{
	Write-Fail "FAIL: 2.2.42"
}
else
{
	Write-Pass "Pass: 2.2.42"
}
}
#2.2.43 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Profile system performance
Write-Testing "TESTING: 2.2.43 (L1) Ensure 'Profile system performance' is set to 'Administrators,NT SERVICE\WdiServiceHost'"
#SetUserRight "SeSystemProfilePrivilege" ($SID_ADMINISTRATORS,$SID_WDI_SYSTEM_SERVICE)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSystemProfilePrivilege')
$out_2_2_43 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeSystemProfilePrivilege')
if ($out_2_2_43 -eq $null)
{
	Write-Fail "FAIL: 2.2.43 (NULL)"
}
else
{
$str = $out_2_2_43 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if (($sid -ne $SID_ADMINISTRATORS) -and ($sid -ne $SID_WDI_SYSTEM_SERVICE))
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -gt 1))
{
	Write-Fail "FAIL: 2.2.43"
}
else
{
	Write-Pass "Pass: 2.2.43"
}
}
#2.2.44 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Replace a process level token
Write-Testing "TESTING: 2.2.44 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
#SetUserRight "SeAssignPrimaryTokenPrivilege" ($SID_LOCAL_SERVICE, $SID_NETWORK_SERVICE)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeAssignPrimaryTokenPrivilege')
$out_2_2_44 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeAssignPrimaryTokenPrivilege')
if ($out_2_2_44 -eq $null)
{
	Write-Fail "FAIL: 2.2.44 (NULL)"
}
else
{
$str = $out_2_2_44 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if (($sid -ne $SID_LOCAL_SERVICE) -and ($sid -ne $SID_NETWORK_SERVICE))
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -gt 1))
{
	Write-Fail "FAIL: 2.2.44"
}
else
{
	Write-Pass "Pass: 2.2.44"
}
}
#2.2.45 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Restore files and directories
Write-Testing "TESTING: 2.2.45 (L1) Ensure 'Restore files and directories' is set to 'Administrators'"
#SetUserRight "SeRestorePrivilege" (,$SID_ADMINISTRATORS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRestorePrivilege')
$out_2_2_45 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeRestorePrivilege')
if ($out_2_2_45 -eq $null)
{
	Write-Fail "FAIL: 2.2.45 (NULL)"
}
else
{
$str = $out_2_2_45 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if ($sid -ne $SID_ADMINISTRATORS)
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -gt 0))
{
	Write-Fail "FAIL: 2.2.45"
}
else
{
	Write-Pass "Pass: 2.2.45"
}
}
#2.2.46 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Shut down the system
Write-Testing "TESTING: 2.2.46 (L1) Ensure 'Shut down the system' is set to 'Administrators'"
#SetUserRight "SeShutdownPrivilege" (,$SID_ADMINISTRATORS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeShutdownPrivilege')
$out_2_2_46 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeShutdownPrivilege')
if ($out_2_2_46 -eq $null)
{
	Write-Fail "FAIL: 2.2.46 (NULL)"
}
else
{
$str = $out_2_2_46 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if ($sid -ne $SID_ADMINISTRATORS)
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -gt 0))
{
	Write-Fail "FAIL: 2.2.46"
}
else
{
	Write-Pass "Pass: 2.2.46"
}
}
#2.2.48 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Take ownership of files or other objects
Write-Testing "TESTING: 2.2.48 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
#SetUserRight "SeTakeOwnershipPrivilege" (,$SID_ADMINISTRATORS)
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeTakeOwnershipPrivilege')
$out_2_2_48 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'SeTakeOwnershipPrivilege')
if ($out_2_2_48 -eq $null)
{
	Write-Fail "FAIL: 2.2.48 (NULL)"
}
else
{
$str = $out_2_2_48 -replace '\s+', '' -split '=' | Select -Index 1
[regex]$regex = ','
$count = $regex.matches($str).count
$condition = 1
for ($num = 0; $num -le ($count); $num++)
{
	$sid = $str -replace '\s+', '' -split ',' | Select -Index $num
	if ($sid -ne $SID_ADMINISTRATORS)
	{
		$condition = 0
	}
}
if (($condition -eq 0) -or ($count -gt 0))
{
	Write-Fail "FAIL: 2.2.48"
}
else
{
	Write-Pass "Pass: 2.2.48"
}
}
Write-Info "---------------------------------------------------"
Write-Info "           Section: 2.3 Security Options"
Write-Info "---------------------------------------------------"
Write-Info "              Section: 2.3.1 Accounts"
Write-Info "---------------------------------------------------"

#2.3.1.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Administrator account status
Write-Testing "TESTING: 2.3.1.1 (L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled'"
#SetSecurityPolicy "EnableAdminAccount" (,"0")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'EnableAdminAccount')
$out_2_3_1_1 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'EnableAdminAccount')
if ($out_2_3_1_1 -eq $null)
{
	Write-Fail "FAIL: 2.3.1.1 (NULL)"
}
else
{
$str = $out_2_3_1_1 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq 0 )
{
	Write-Pass "PASS: 2.3.1.1"
}
else
{
	Write-Fail "FAIL: 2.3.1.1"
}
}
#2.3.1.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Block Microsoft accounts
#TODO
Write-Testing "2.3.1.2 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser" (,"4,3")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser')
$out_2_3_1_2 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser')
if ($out_2_3_1_2 -eq $null)
{
	Write-Fail "FAIL: 2.3.1.2 (NULL)"
}
else
{
$str = $out_2_3_1_2 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,3" )
{
	Write-Pass "PASS: 2.3.1.2"
}
else
{
	Write-Fail "FAIL: 2.3.1.2"
}
}
#2.3.1.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Guest account status
Write-Testing "TESTING: 2.3.1.3 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'"
#SetSecurityPolicy "EnableGuestAccount" (,"0")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'EnableGuestAccount')
$out_2_3_1_3 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'EnableGuestAccount')
if ($out_2_3_1_3 -eq $null)
{
	Write-Fail "FAIL: 2.3.1.3 (NULL)"
}
else
{
$str = $out_2_3_1_1 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq 0 )
{
	Write-Pass "PASS: 2.3.1.3"
}
else
{
	Write-Fail "FAIL: 2.3.1.3"
}
}
#2.3.1.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Limit local account use of blank passwords to console logon only
Write-Testing "TESTING: 2.3.1.4 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse')
$out_2_3_1_4 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse')
if ($out_2_3_1_4 -eq $null)
{
	Write-Fail "FAIL: 2.3.1.4 (NULL)"
}
else
{
$str = $out_2_3_1_4 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.1.4"
}
else
{
	Write-Fail "FAIL: 2.3.1.4"
}
}
#2.3.1.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Rename administrator account
Write-Testing "TESTING: 2.3.1.5 (L1) Configure 'Accounts: Rename administrator account'"
#SetSecurityPolicy "NewAdministratorName" (,"`"$($AdminNewAccountName)`"")
#Set-LocalUser -Name $AdminNewAccountName -Description " "
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'NewAdministratorName')
$out_2_3_1_5 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'NewAdministratorName')
if ($out_2_3_1_5 -eq $null)
{
	Write-Fail "FAIL: 2.3.1.5 (NULL)"
}
else
{
$str = $out_2_3_1_5 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq '"Administrator"' )
{
	Write-Fail "FAIL: 2.3.1.5"
}
else
{
	Write-Pass "PASS: 2.3.1.5"
}
}
#2.3.1.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Accounts: Rename guest account
Write-Testing "TESTING: 2.3.1.6 (L1) Configure 'Accounts: Rename guest account'"
#SetSecurityPolicy "NewGuestName" (,"`"$($GuestNewAccountName)`"")
#Set-LocalUser -Name $GuestNewAccountName -Description " "
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'NewGuestName')
$out_2_3_1_6 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'NewGuestName')
if ($out_2_3_1_6 -eq $null)
{
	Write-Fail "FAIL: 2.3.1.6 (NULL)"
}
else
{
$str = $out_2_3_1_6 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq '"Guest"' )
{
	Write-Fail "FAIL: 2.3.1.6"
}
else
{
	Write-Pass "PASS: 2.3.1.6"
}
}
#2.3.2.1 =>Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings
Write-Testing "TESTING: 2.3.2.1 (L1) Ensure 'Audit: Force audit policy subcategory settings to override audit policy category settings' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy')
$out_2_3_2_1 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy')
if ($out_2_3_2_1 -eq $null)
{
	Write-Fail "FAIL: 2.3.2.1 (NULL)"
}
else
{
$str = $out_2_3_2_1 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.2.1"
}
else
{
	Write-Fail "FAIL: 2.3.2.1"
}
}

#2.3.2.2 Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Audit: Shut down system immediately if unable to log security audits
Write-Testing "TESTING: 2.3.2.2 (L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail" (,"4,0")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail')
$out_2_3_2_2 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail')
if ($out_2_3_2_2 -eq $null)
{
	Write-Fail "FAIL: 2.3.2.2 (NULL)"
}
else
{
$str = $out_2_3_2_2 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,0" )
{
	Write-Pass "PASS: 2.3.2.2"
}
else
{
	Write-Fail "FAIL: 2.3.2.2"
}
}
#2.3.4.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Devices: Allowed to format and eject removable media
Write-Testing "TESTING: 2.3.4.1 (L1) Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD" (,"1,`"0`"")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD')
$out_2_3_4_1 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD')
if ($out_2_3_4_1 -eq $null)
{
	Write-Fail "FAIL: 2.3.4.1 (NULL)"
}
else
{
$str = $out_2_3_4_1 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "1,0" )
{
	Write-Pass "PASS: 2.3.4.1"
}
else
{
	Write-Fail "FAIL: 2.3.4.1"
}
}

#2.3.4.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Devices: Prevent users from installing printer drivers
Write-Testing "TESTING: 2.3.4.2 (L1) Ensure 'Devices: Prevent users from installing printer drivers'is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers')
$out_2_3_4_2 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers')
if ($out_2_3_4_2 -eq $null)
{
	Write-Fail "FAIL: 2.3.4.2 (NULL)"
}
else
{
$str = $out_2_3_4_2 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.4.2"
}
else
{
	Write-Fail "FAIL: 2.3.4.2"
}
}
#2.3.6.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Digitally encrypt or sign secure channel data (always)
Write-Testing "TESTING: 2.3.6.1 (L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal')
$out_2_3_6_1 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal')
if ($out_2_3_6_1 -eq $null)
{
	Write-Fail "FAIL: 2.3.6.1 (NULL)"
}
else
{
$str = $out_2_3_6_1 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.6.1"
}
else
{
	Write-Fail "FAIL: 2.3.6.1"
}
}
#2.3.6.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Digitally encrypt secure channel data (when possible)
Write-Testing "TESTING: 2.3.6.2 (L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel')
$out_2_3_6_2 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel')
if ($out_2_3_6_2 -eq $null)
{
	Write-Fail "FAIL: 2.3.6.2 (NULL)"
}
else
{
$str = $out_2_3_6_2 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.6.2"
}
else
{
	Write-Fail "FAIL: 2.3.6.2"
}
}
#2.3.6.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Digitally sign secure channel data (when possible)
Write-Testing "TESTING: 2.3.6.3 (L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel')
$out_2_3_6_3 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel')
if ($out_2_3_6_3 -eq $null)
{
	Write-Fail "FAIL: 2.3.6.3 (NULL)"
}
else
{
$str = $out_2_3_6_3 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.6.3"
}
else
{
	Write-Fail "FAIL: 2.3.6.3"
}
}
#2.3.6.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Disable machine account password changes
Write-Testing "TESTING: 2.3.6.4 (L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange" (,"4,0")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange')
$out_2_3_6_4 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange')
if ($out_2_3_6_4 -eq $null)
{
	Write-Fail "FAIL: 2.3.6.4 (NULL)"
}
else
{
$str = $out_2_3_6_4 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,0" )
{
	Write-Pass "PASS: 2.3.6.4"
}
else
{
	Write-Fail "FAIL: 2.3.6.4"
}
}
#2.3.6.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Maximum machine account password age
Write-Testing "TESTING: 2.3.6.5 (L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge" (,"4,30")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge')
$out_2_3_6_5 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge')
if ($out_2_3_6_5 -eq $null)
{
	Write-Fail "FAIL: 2.3.6.5 (NULL)"
}
else
{
$str = $out_2_3_6_5 -replace '\s+', '' -split '=' | Select -Index 1
$str2 = $str -replace '\s+', '' -split ',' | Select -Index 1
[int]$str3 = $str2 -replace '\D'
if ( $str3 -le "30" )
{
	Write-Pass "PASS: 2.3.6.5"
}
else
{
	Write-Fail "FAIL: 2.3.6.5"
}
}
#2.3.6.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Domain member: Require strong (Windows 2000 or later) session key
Write-Testing "TESTING: 2.3.6.6 (L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey')
$out_2_3_6_6 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey')
if ($out_2_3_6_6 -eq $null)
{
	Write-Fail "FAIL: 2.3.6.6 (NULL)"
}
else
{
$str = $out_2_3_6_6 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.6.6"
}
else
{
	Write-Fail "FAIL: 2.3.6.6"
}
}
#2.3.7.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Do not require CTRL+ALT+DEL
Write-Testing "TESTING: 2.3.7.1 (L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD" (,"4,0")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD')
$out_2_3_7_1 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD')
if ($out_2_3_7_1 -eq $null)
{
	Write-Fail "FAIL: 2.3.7.1 (NULL)"
}
else
{
$str = $out_2_3_7_1 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,0" )
{
	Write-Pass "PASS: 2.3.7.1"
}
else
{
	Write-Fail "FAIL: 2.3.7.1"
}
}  

#2.3.7.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Don't display last signed-in
Write-Testing "TESTING: 2.3.7.2 (L1) Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName" (,"4,0")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName')
$out_2_3_7_2 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName')
if ($out_2_3_7_2 -eq $null)
{
	Write-Fail "FAIL: 2.3.7.2 (NULL)"
}
else
{
$str = $out_2_3_7_2 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,0" )
{
	Write-Pass "PASS: 2.3.7.2"
}
else
{
	Write-Fail "FAIL: 2.3.7.2"
}
}  
#2.3.7.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Machine inactivity limit
Write-Testing "TESTING: 2.3.7.3 (L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0' "
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs" (,"4,900")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs')
$out_2_3_7_3 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs')
if ($out_2_3_7_3 -eq $null)
{
	Write-Fail "FAIL: 2.3.7.3 (NULL)"
}
else
{
$str = $out_2_3_7_3 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,900" )
{
	Write-Pass "PASS: 2.3.7.3"
}
else
{
	Write-Fail "FAIL: 2.3.7.3"
}
}  
  
#2.3.7.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Message text for users attempting to log on
#Write-Testing "TESTING: 2.3.7.4 (L1) Configure 'Interactive logon: Message text for users attempting to log on'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText" ("7",$LogonLegalNoticeMessage)
 
#2.3.7.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Message title for users attempting to log on
#Write-Testing "TESTING: 2.3.7.5 (L1) Configure 'Interactive logon: Message title for users attempting to log on'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption" (,"1,`"$($LogonLegalNoticeMessageTitle)`"")
  
#2.3.7.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Number of previous logons to cache (in case domain controller is not available)
Write-Testing "TESTING: 2.3.7.6 (L2) Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount" (,"1,`"4`"")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount')
$out_2_3_7_6 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount')
if ($out_2_3_7_6 -eq $null)
{
	Write-Fail "FAIL: 2.3.7.6 (NULL)"
}
else
{
$str = $out_2_3_7_6 -replace '\s+', '' -split '=' | Select -Index 1
$str2 = $str -replace '\s+', '' -split ',' | Select -Index 1
[int]$str3 = $str2 -replace '\D'
if ( $str3 -le "4" )
{
	Write-Pass "PASS: 2.3.7.6"
}
else
{
	Write-Fail "FAIL: 2.3.7.6"
}
}
#2.3.7.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Prompt user to change password before expiration
Write-Testing "TESTING: 2.3.7.7 (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning" (,"4,5")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning')
$out_2_3_7_7 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning')
if ($out_2_3_7_7 -eq $null)
{
	Write-Fail "FAIL: 2.3.7.7 (NULL)"
}
else
{
$str = $out_2_3_7_7 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,5" )
{
	Write-Pass "PASS: 2.3.7.7"
}
else
{
	Write-Fail "FAIL: 2.3.7.7"
}
}
   
#2.3.7.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Require Domain Controller Authentication to unlock workstation
Write-Testing "TESTING: 2.3.7.8 (L1) Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon')
$out_2_3_7_8 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon')
if ($out_2_3_7_8 -eq $null)
{
	Write-Fail "FAIL: 2.3.7.8 (NULL)"
}
else
{
$str = $out_2_3_7_8 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.7.8"
}
else
{
	Write-Fail "FAIL: 2.3.7.8"
}
}
#2.3.7.9 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Interactive logon: Smart card removal behavior
Write-Testing "TESTING: 2.3.7.9 (L1) Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption" (,"1,`"1`"")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption')
$out_2_3_7_9 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption')
if ($out_2_3_7_9 -eq $null)
{
	Write-Fail "FAIL: 2.3.7.9 (NULL)"
}
else
{
$str = $out_2_3_7_9 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "1,1" )
{
	Write-Pass "PASS: 2.3.7.9"
}
else
{
	Write-Fail "FAIL: 2.3.7.9"
}
}

#2.3.8.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network client: Digitally sign communications (always)
Write-Testing "TESTING: 2.3.8.1 (L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature')
$out_2_3_8_1 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature')
if ($out_2_3_8_1 -eq $null)
{
	Write-Fail "FAIL: 2.3.8.1 (NULL)"
}
else
{
$str = $out_2_3_8_1 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.8.1"
}
else
{
	Write-Fail "FAIL: 2.3.8.1"
}
}
#2.3.8.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network client: Digitally sign communications (if server agrees)
Write-Testing "TESTING: 2.3.8.2 (L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled' "
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature')
$out_2_3_8_2 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature')
if ($out_2_3_8_2 -eq $null)
{
	Write-Fail "FAIL: 2.3.8.2 (NULL)"
}
else
{
$str = $out_2_3_8_2 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.8.2"
}
else
{
	Write-Fail "FAIL: 2.3.8.2"
}
}
#2.3.8.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network client: Send unencrypted password to third-party SMB servers
Write-Testing "TESTING: 2.3.8.3 (L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword" (,"4,0")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword')
$out_2_3_8_3 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword')
if ($out_2_3_8_3 -eq $null)
{
	Write-Fail "FAIL: 2.3.8.3 (NULL)"
}
else
{
$str = $out_2_3_8_3 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,0" )
{
	Write-Pass "PASS: 2.3.8.3"
}
else
{
	Write-Fail "FAIL: 2.3.8.3"
}
}
#2.3.9.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Amount of idle time required before suspending session
Write-Testing "TESTING: 2.3.9.1 (L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect" (,"4,15")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect')
$out_2_3_9_1 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect')
if ($out_2_3_9_1 -eq $null)
{
	Write-Fail "FAIL: 2.3.9.1 (NULL)"
}
else
{
$str = $out_2_3_9_1 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,15" )
{
	Write-Pass "PASS: 2.3.9.1"
}
else
{
	Write-Fail "FAIL: 2.3.9.1"
}
}

#2.3.9.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Digitally sign communications (always)
Write-Testing "TESTING: 2.3.9.2 (L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature')
$out_2_3_9_2 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature')
if ($out_2_3_9_2 -eq $null)
{
	Write-Fail "FAIL: 2.3.9.2 (NULL)"
}
else
{
$str = $out_2_3_9_2 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.9.2"
}
else
{
	Write-Fail "FAIL: 2.3.9.2"
}
}
#2.3.9.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Digitally sign communications (if client agrees)
Write-Testing "TESTING: 2.3.9.3 (L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature')
$out_2_3_9_3 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature')
if ($out_2_3_9_3 -eq $null)
{
	Write-Fail "FAIL: 2.3.9.3 (NULL)"
}
else
{
$str = $out_2_3_9_3 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.9.3"
}
else
{
	Write-Fail "FAIL: 2.3.9.3"
}
}
#2.3.9.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Disconnect clients when logon hours expire
Write-Testing "TESTING: 2.3.9.4 (L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff')
$out_2_3_9_4 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff')
if ($out_2_3_9_4 -eq $null)
{
	Write-Fail "FAIL: 2.3.9.4 (NULL)"
}
else
{
$str = $out_2_3_9_4 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.9.4"
}
else
{
	Write-Fail "FAIL: 2.3.9.4"
}
}
#2.3.9.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Microsoft network server: Server SPN target name validation level
Write-Testing "TESTING: 2.3.9.5 (L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel')
$out_2_3_9_5 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel')
if ($out_2_3_9_5 -eq $null)
{
	Write-Fail "FAIL: 2.3.9.5 (NULL)"
}
else
{
$str = $out_2_3_9_5 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.9.5"
}
else
{
	Write-Fail "FAIL: 2.3.9.5"
}
}

#2.3.10.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Allow anonymous SID/Name translation
Write-Testing "TESTING: 2.3.10.1 (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'"
#SetSecurityPolicy "LSAAnonymousNameLookup" (,"0")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'LSAAnonymousNameLookup')
$out_2_3_10_1 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'LSAAnonymousNameLookup')
if ($out_2_3_10_1 -eq $null)
{
	Write-Fail "FAIL: 2.3.10.1 (NULL)"
}
else
{
$str = $out_2_3_10_1 -replace '\s+', '' -split '=' | Select -Index 1
[int]$str3 = $str -replace '\D'
if ( $str3 -eq "0" )
{
	Write-Pass "PASS: 2.3.10.1"
}
else
{
	Write-Fail "FAIL: 2.3.10.1"
}  
}
#2.3.10.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Do not allow anonymous enumeration of SAM accounts
Write-Testing "TESTING: 2.3.10.2 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM')
$out_2_3_10_2 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM')
if ($out_2_3_10_2 -eq $null)
{
	Write-Fail "FAIL: 2.3.10.2 (NULL)"
}
else
{
$str = $out_2_3_10_2 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.10.2"
}
else
{
	Write-Fail "FAIL: 2.3.10.2"
}
}
#2.3.10.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Do not allow anonymous enumeration of SAM accounts and shares
#TODO
Write-Testing "TESTING: 2.3.10.3 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous')
$out_2_3_10_3 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous')
if ($out_2_3_10_3 -eq $null)
{
	Write-Fail "FAIL: 2.3.10.3 (NULL)"
}
else
{
$str = $out_2_3_10_3 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.10.3"
}
else
{
	Write-Fail "FAIL: 2.3.10.3"
}
}
#2.3.10.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Do not allow storage of passwords and credentials for network authentication
Write-Testing "TESTING: 2.3.10.4 (L2) Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds')
$out_2_3_10_4 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds')
if ($out_2_3_10_4 -eq $null)
{
	Write-Fail "FAIL: 2.3.10.4 (NULL)"
}
else
{
$str = $out_2_3_10_4 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.10.4"
}
else
{
	Write-Fail "FAIL: 2.3.10.4"
}
}
#2.3.10.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Let Everyone permissions apply to anonymous users
Write-Testing "TESTING: 2.3.10.5 (L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous" (,"4,0")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous')
$out_2_3_10_5 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous')
if ($out_2_3_10_5 -eq $null)
{
	Write-Fail "FAIL: 2.3.10.5 (NULL)"
}
else
{
$str = $out_2_3_10_5 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,0" )
{
	Write-Pass "PASS: 2.3.10.5"
}
else
{
	Write-Fail "FAIL: 2.3.10.5"
}
}
#2.3.10.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Named Pipes that can be accessed anonymously
Write-Testing "TESTING: 2.3.10.7 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes" ("7", " ")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes')
$out_2_3_10_7 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes')
if ($out_2_3_10_7 -eq $null)
{
	Write-Fail "FAIL: 2.3.10.7 (NULL)"
}
else
{
$str = $out_2_3_10_7 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "7," )
{
	Write-Pass "PASS: 2.3.10.7"
}
else
{
	Write-Fail "FAIL: 2.3.10.7"
}
}
#2.3.10.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Remotely accessible registry paths
Write-Testing "TESTING: 2.3.10.8 (L1) Configure 'Network access: Remotely accessible registry paths'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine" (
#        "7",
#        "System\CurrentControlSet\Control\ProductOptions",
#        "System\CurrentControlSet\Control\Server Applications",
#        "Software\Microsoft\Windows NT\CurrentVersion")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine')
$out_2_3_10_8 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine')
if ($out_2_3_10_8 -eq $null)
{
	Write-Fail "FAIL: 2.3.10.8 (NULL)"
}
else
{
$str = $out_2_3_10_8 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "7,System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\ServerApplications,Software\Microsoft\WindowsNT\CurrentVersion" )
{
	Write-Pass "PASS: 2.3.10.8"
}
else
{
	Write-Fail "FAIL: 2.3.10.8"
}
}
#2.3.10.9 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Remotely accessible registry paths and sub-paths
Write-Testing "TESTING: 2.3.10.9 (L1) Configure 'Network access: Remotely accessible registry paths and sub-paths'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine" (
#        "7",
#        "System\CurrentControlSet\Control\Print\Printers",
#        "System\CurrentControlSet\Services\Eventlog",
#        "Software\Microsoft\OLAP Server",
#        "Software\Microsoft\Windows NT\CurrentVersion\Print",
#        "Software\Microsoft\Windows NT\CurrentVersion\Windows",
#        "System\CurrentControlSet\Control\ContentIndex",
#        "System\CurrentControlSet\Control\Terminal Server",
#        "System\CurrentControlSet\Control\Terminal Server\UserConfig",
#        "System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration",
#        "Software\Microsoft\Windows NT\CurrentVersion\Perflib",
#        "System\CurrentControlSet\Services\SysmonLog")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine')
$out_2_3_10_9 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine')
if ($out_2_3_10_9 -eq $null)
{
	Write-Fail "FAIL: 2.3.10.9 (NULL)"
}
else
{
$str = $out_2_3_10_9 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "7,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAPServer,Software\Microsoft\WindowsNT\CurrentVersion\Print,Software\Microsoft\WindowsNT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\TerminalServer,System\CurrentControlSet\Control\TerminalServer\UserConfig,System\CurrentControlSet\Control\TerminalServer\DefaultUserConfiguration,Software\Microsoft\WindowsNT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog" )
{
	Write-Pass "PASS: 2.3.10.9"
}
else
{
	Write-Fail "FAIL: 2.3.10.9"
}
}
#2.3.10.10 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Restrict anonymous access to Named Pipes and Shares
Write-Testing "TESTING: 2.3.10.10 (L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess')
$out_2_3_10_10 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess')
if ($out_2_3_10_10 -eq $null)
{
	Write-Fail "FAIL: 2.3.10.10 (NULL)"
}
else
{
$str = $out_2_3_10_10 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.10.10"
}
else
{
	Write-Fail "FAIL: 2.3.10.10"
}
}
#2.3.10.11 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Restrict clients allowed to make remote calls to SAM
Write-Testing "TESTING: 2.3.10.11 (L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM" (,"1,O:BAG:BAD:(A;;RC;;;BA)")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM')
$out_2_3_10_11 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM')
if ($out_2_3_10_11 -eq $null)
{
	Write-Fail "FAIL: 2.3.10.11 (NULL)"
}
else
{
$str = $out_2_3_10_11 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "1,O:BAG:BAD:(A;;RC;;;BA)" )
{
	Write-Pass "PASS: 2.3.10.11"
}
else
{
	Write-Fail "FAIL: 2.3.10.11"
}
}

#2.3.10.12 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Shares that can be accessed anonymously
Write-Testing "TESTING: 2.3.10.12 (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares" (,"7,")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares')
$out_2_3_10_12 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares')
if ($out_2_3_10_12 -eq $null)
{
	Write-Fail "FAIL: 2.3.10.12 (NULL)"
}
else
{
$str = $out_2_3_10_12 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "7" )
{
	Write-Pass "PASS: 2.3.10.12"
}
else
{
	Write-Fail "FAIL: 2.3.10.12"
}
}

#2.3.10.13 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network access: Sharing and security model for local accounts
Write-Testing "TESTING: 2.3.10.13 (L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest" (,"4,0")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest')
$out_2_3_10_13 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest')
if ($out_2_3_10_13 -eq $null)
{
	Write-Fail "FAIL: 2.3.10.13 (NULL)"
}
else
{
$str = $out_2_3_10_13 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,0" )
{
	Write-Pass "PASS: 2.3.10.13"
}
else
{
	Write-Fail "FAIL: 2.3.10.13"
}
}
#2.3.11.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Allow Local System to use computer identity for NTLM
Write-Testing "TESTING: 2.3.11.1 (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId')
$out_2_3_11_1 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId')
if ($out_2_3_11_1 -eq $null)
{
	Write-Fail "FAIL: 2.3.11.1 (NULL)"
}
else
{
$str = $out_2_3_11_1 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.11.1"
}
else
{
	Write-Fail "FAIL: 2.3.11.1"
}
}

#2.3.11.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Allow LocalSystem NULL session fallback
Write-Testing "TESTING: 2.3.11.2 (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback " (,"4,0")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback')
$out_2_3_11_2 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback')
if ($out_2_3_11_2 -eq $null)
{
	Write-Fail "FAIL: 2.3.11.2 (NULL)"
}
else
{
$str = $out_2_3_11_2 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,0" )
{
	Write-Pass "PASS: 2.3.11.2"
}
else
{
	Write-Fail "FAIL: 2.3.11.2"
}
}
  
#2.3.11.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network Security: Allow PKU2U authentication requests to this computer to use online identities
Write-Testing "TESTING: 2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID " (,"4,0")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID')
$out_2_3_11_3 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID')
if ($out_2_3_11_3 -eq $null)
{
	Write-Fail "FAIL: 2.3.11.3 (NULL)"
}
else
{
$str = $out_2_3_11_3 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,0" )
{
	Write-Pass "PASS: 2.3.11.3"
}
else
{
	Write-Fail "FAIL: 2.3.11.3"
}
}
#2.3.11.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Configure encryption types allowed for Kerberos
Write-Testing "TESTING: 2.3.11.4 (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes" (,"4,2147483640")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes')
$out_2_3_11_4 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes')
if ($out_2_3_11_4 -eq $null)
{
	Write-Fail "FAIL: 2.3.11.4 (NULL)"
}
else
{
$str = $out_2_3_11_4 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,2147483640" )
{
	Write-Pass "PASS: 2.3.11.4"
}
else
{
	Write-Fail "FAIL: 2.3.11.4"
}
}
  
#2.3.11.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Do not store LAN Manager hash value on next password change 
Write-Testing "TESTING: 2.3.11.5 Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash')
$out_2_3_11_5 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash')
if ($out_2_3_11_5 -eq $null)
{
	Write-Fail "FAIL: 2.3.11.5 (NULL)"
}
else
{
$str = $out_2_3_11_5 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.11.5"
}
else
{
	Write-Fail "FAIL: 2.3.11.5"
}
}
#2.3.11.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Force logoff when logon hours expire
Write-Testing "TESTING: 2.3.11.6 Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'"
#SetSecurityPolicy "ForceLogoffWhenHourExpire" (,"1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'ForceLogoffWhenHourExpire')
$out_2_3_11_6 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'ForceLogoffWhenHourExpire')
if ($out_2_3_11_6 -eq $null)
{
	Write-Fail "FAIL: 2.3.11.6 (NULL)"
}
else
{
$str = $out_2_3_11_6 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq ",1" )
{
	Write-Pass "PASS: 2.3.11.6"
}
else
{
	Write-Fail "FAIL: 2.3.11.6"
}
}
#2.3.11.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: LAN Manager authentication level
Write-Testing "TESTING: 2.3.11.7 Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel" (,"4,5")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel')
$out_2_3_11_7 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel')
if ($out_2_3_11_7 -eq $null)
{
	Write-Fail "FAIL: 2.3.11.7 (NULL)"
}
else
{
$str = $out_2_3_11_7 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,5" )
{
	Write-Pass "PASS: 2.3.11.7"
}
else
{
	Write-Fail "FAIL: 2.3.11.7"
}
}
   
#2.3.11.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: LDAP client signing requirements
Write-Testing "TESTING: 2.3.11.8 Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity')
$out_2_3_11_8 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity')
if ($out_2_3_11_8 -eq $null)
{
	Write-Fail "FAIL: 2.3.11.8 (NULL)"
}
else
{
$str = $out_2_3_11_8 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.11.8"
}
else
{
	Write-Fail "FAIL: 2.3.11.8"
}
}
#2.3.11.9 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Minimum session security for NTLM SSP based (including secure RPC) clients
Write-Testing "TESTING: 2.3.11.9 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec" (,"4,537395200")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec')
$out_2_3_11_9 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec')
if ($out_2_3_11_9 -eq $null)
{
	Write-Fail "FAIL: 2.3.11.9 (NULL)"
}
else
{
$str = $out_2_3_11_9 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,537395200" )
{
	Write-Pass "PASS: 2.3.11.9"
}
else
{
	Write-Fail "FAIL: 2.3.11.9"
}
}
#2.3.11.10 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Minimum session security for NTLM SSP based (including secure RPC) servers
Write-Testing "TESTING: 2.3.11.10 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec" (,"4,537395200")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec')
$out_2_3_11_10 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec')
if ($out_2_3_11_10 -eq $null)
{
	Write-Fail "FAIL: 2.3.11.10 (NULL)"
}
else
{
$str = $out_2_3_11_10 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,537395200" )
{
	Write-Pass "PASS: 2.3.11.10"
}
else
{
	Write-Fail "FAIL: 2.3.11.10"
}
}
#2.3.13.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Shutdown: Allow system to be shut down without having to log on
Write-Testing "TESTING: 2.3.13.1 (L1) Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon" (,"4,0")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon')
$out_2_3_13_1 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon')
if ($out_2_3_13_1 -eq $null)
{
	Write-Fail "FAIL: 2.3.13.1 (NULL)"
}
else
{
$str = $out_2_3_13_1 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,0" )
{
	Write-Pass "PASS: 2.3.13.1"
}
else
{
	Write-Fail "FAIL: 2.3.13.1"
}
}
#2.3.15.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\System objects: Require case insensitivity for non Windows subsystems
Write-Testing "TESTING: 2.3.15.1 (L1) Ensure 'System objects: Require case insensitivity for nonWindows subsystems' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive" (, "4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive')
$out_2_3_15_1 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive')
if ($out_2_3_15_1 -eq $null)
{
	Write-Fail "FAIL: 2.3.15.1 (NULL)"
}
else
{
$str = $out_2_3_15_1 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.15.1"
}
else
{
	Write-Fail "FAIL: 2.3.15.1"
}
}
#2.3.15.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)
Write-Testing "TESTING: 2.3.15.2 (L1) Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode')
$out_2_3_15_2 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode')
if ($out_2_3_15_2 -eq $null)
{
	Write-Fail "FAIL: 2.3.15.2 (NULL)"
}
else
{
$str = $out_2_3_15_2 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.15.2"
}
else
{
	Write-Fail "FAIL: 2.3.15.2"
}
}
#2.3.17.1 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Admin Approval Mode for the Built-in Administrator account
Write-Testing "TESTING: 2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken')
$out_2_3_17_1 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken')
if ($out_2_3_17_1 -eq $null)
{
	Write-Fail "FAIL: 2.3.17.1 (NULL)"
}
else
{
$str = $out_2_3_17_1 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.17.1"
}
else
{
	Write-Fail "FAIL: 2.3.17.1"
}
}
#2.3.17.2 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode
Write-Testing "TESTING: 2.3.17.2 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin" (,"4,2")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin')
$out_2_3_17_2 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin')
if ($out_2_3_17_2 -eq $null)
{
	Write-Fail "FAIL: 2.3.17.2 (NULL)"
}
else
{
$str = $out_2_3_17_2 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,2" )
{
	Write-Pass "PASS: 2.3.17.2"
}
else
{
	Write-Fail "FAIL: 2.3.17.2"
}
}
#2.3.17.3 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Behavior of the elevation prompt for standard users
Write-Testing "TESTING: 2.3.17.3 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser" (,"4,0")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser')
$out_2_3_17_3 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser')
if ($out_2_3_17_3 -eq $null)
{
	Write-Fail "FAIL: 2.3.17.3 (NULL)"
}
else
{
$str = $out_2_3_17_3 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,0" )
{
	Write-Pass "PASS: 2.3.17.3"
}
else
{
	Write-Fail "FAIL: 2.3.17.3"
}
}
#2.3.17.4 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Detect application installations and prompt for elevation
Write-Testing "TESTING: 2.3.17.4 (L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection" (,"4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection')
$out_2_3_17_4 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection')
if ($out_2_3_17_4 -eq $null)
{
	Write-Fail "FAIL: 2.3.17.4 (NULL)"
}
else
{
$str = $out_2_3_17_4 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.17.4"
}
else
{
	Write-Fail "FAIL: 2.3.17.4"
}
}	
#2.3.17.5 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Only elevate UIAccess applications that are installed in secure location
Write-Testing "TESTING: 2.3.17.5 (L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths" (, "4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths')
$out_2_3_17_5 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths')
if ($out_2_3_17_5 -eq $null)
{
	Write-Fail "FAIL: 2.3.17.5 (NULL)"
}
else
{
$str = $out_2_3_17_5 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.17.5"
}
else
{
	Write-Fail "FAIL: 2.3.17.5"
}
}
#2.3.17.6 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Run all administrators in Admin Approval Mode
Write-Testing "TESTING: 2.3.17.6 (L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA" (, "4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA')
$out_2_3_17_6 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA')
if ($out_2_3_17_6 -eq $null)
{
	Write-Fail "FAIL: 2.3.17.6 (NULL)"
}
else
{
$str = $out_2_3_17_6 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.17.6"
}
else
{
	Write-Fail "FAIL: 2.3.17.6"
}
}
#2.3.17.7 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Switch to the secure desktop when prompting for elevation
Write-Testing "TESTING: 2.3.17.7 (L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop" (, "4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop')
$out_2_3_17_7 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop')
if ($out_2_3_17_7 -eq $null)
{
	Write-Fail "FAIL: 2.3.17.7 (NULL)"
}
else
{
$str = $out_2_3_17_7 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.17.7"
}
else
{
	Write-Fail "FAIL: 2.3.17.7"
}
}
#2.3.17.8 => Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\User Account Control: Virtualize file and registry write failures to per-user locations
Write-Testing "TESTING: 2.3.17.8 (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'"
#SetSecurityPolicy "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization" (, "4,1")
Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization')
$out_2_3_17_8 = Write-Output (Get-Content ${env:appdata}\secpol.cfg | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization')
if ($out_2_3_17_8 -eq $null)
{
	Write-Fail "FAIL: 2.3.17.8 (NULL)"
}
else
{
$str = $out_2_3_17_8 -replace '\s+', '' -split '=' | Select -Index 1
if ( $str -eq "4,1" )
{
	Write-Pass "PASS: 2.3.17.8"
}
else
{
	Write-Fail "FAIL: 2.3.17.8"
}
}
Write-Info "---------------------------------------------------"
Write-Info "                      END"
Write-Info "---------------------------------------------------"
	
	
	
	
	
	
	
	
	
	
	