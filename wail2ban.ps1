################################################################################
#                        _ _ ____  _                 
#         __      ____ _(_) |___ \| |__   __ _ _ __  
#         \ \ /\ / / _` | | | __) | '_ \ / _` | '_ \ 
#          \ V  V / (_| | | |/ __/| |_) | (_| | | | |
#           \_/\_/ \__,_|_|_|_____|_.__/ \__,_|_| |_|
#   
################################################################################
# 
# For help, read the below function. 
#
function help { 
	"`nwail2ban   `n"
	"wail2ban is an attempt to recreate fail2ban for windows, hence [w]indows f[ail2ban]."
	" "
	"wail2ban takes configured events known to be audit failures, or similar, checks for "+`
	"IPs in the event message, and given sufficient failures, bans them for a small amount"+`
	"of time."
	" "
	"Settings: "
	" -config    : show the settings that are being used "
	" -jail      : show the currently banned IPs"
	" -jailbreak : bust out all the currently banned IPs"	
	" -nopoll		 : wait for events instead of polling (default false). Note that bans do not expire then properly"
	" -recidive  : use exponential ban duration with base 2"
	" -help      : This message."
	" "
}


$DebugPreference = "continue"
# $DebugPreference = "inquire"

################################################################################
# Constants

# $CHECK_WINDOW = 120  # We check the most recent X seconds of log.         Default: 120
$CHECK_WINDOW = 600  # We check the most recent X seconds of log.         Default: 120
$CHECK_COUNT  = 5    # Ban after this many failures in search period.     Default: 5
# $MAX_BANDURATION = 7776000 # 3 Months in seconds
$MAX_BANDURATION = 86400 # 1 Day in seconds
$MIN_BANDURATION = 600		# roland
$POLL_INTERVAL = 60			# roland
$MAIL_TO = "roland@pinal.ee"			# roland
$PSEmailServer = "192.168.2.145"		# roland
$SMTP_PORT = 25			# roland			
	
################################################################################
# Files

$wail2banInstall = "" + (Get-Location) + "\"
$wail2banScript  = $wail2banInstall + "wail2ban.ps1"
$logFile         = $wail2banInstall + "wail2ban_log.log"
$ConfigFile      = $wail2banInstall + "wail2ban_config.ini"
$BannedIPLog	 = $wail2banInstall + "bannedIPLog.ini"

################################################################################
# Constructs

$RecordEventLog     = "Application"     # Where we store our own event messages
$FirewallRulePrefix = "wail2ban block:" # What we name our Rules
$HostName			= [System.Net.Dns]::GetHostName()		# roland

# $EventTypes = "Application,Security,System"	  #Event logs we allow to be processed 	# cob roland
$EventTypes = "Application,Security,System,OpenSSH/Operational"	  #Event logs we allow to be processed		# roland

New-Variable -Name RegexIP -Force -Value ([regex]'(?<First>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Second>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Third>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Fourth>2[0-4]\d|25[0-5]|[01]?\d\d?)')

# Ban Count structure
$BannedIPs = @{}
# Incoming event structure
$CheckEvents = New-object system.data.datatable("CheckEvents")
$null = $CheckEvents.columns.add("EventLog")
$null = $CheckEvents.columns.add("EventID")
$null = $CheckEvents.columns.add("EventDescription")
	  
$WhiteList = @()
#$host.UI.RawUI.BufferSize = new-object System.Management.Automation.Host.Size(100,50)

$OSVersion = invoke-expression "wmic os get Caption /value"
$BLOCK_TYPE = "NETSH"

# Grep configuration file 
switch -regex -file $ConfigFile {
    "^\[(.+)\]$" {
		$Header = $matches[1].Trim()
    }
	# "^\s*([^#].+?)\s*=\s*(.*)" {		# cob roland: this requires 2 or more numbers in the event id
	"^\s*([^#].*?)\s*=\s*(.*)" { 		# roland: this requires 1 or more numbers in the event id

		$Match1 = $matches[1]
		$Match2 = $matches[2]
			
		if ($EventTypes -match $Header) { 
			$row = $CheckEvents.NewRow()
			$row.EventLog = $Header
			$row.EventID = $Match1
			$row.EventDescription = $Match2
			$CheckEvents.Rows.Add($row)
		} else { 
			switch ($Header) { 
				"Whitelist" { $WhiteList += $Match1; }		
			}	
		}
    }
	
} 


# We also want to whitelist this machine's NICs.
$SelfList = @() 
foreach ($listing in ((ipconfig | findstr [0-9].\.))) {
	if ($listing -match "Address") { 	
		$SelfList += $listing.Split()[-1] 
	}
} 

################################################################################
# Functions

function event ($text,$task,$result) { 
	$event = new-object System.Diagnostics.EventLog($RecordEventLog)
	$event.Source = "wail2ban"
	switch  ($task) { 
		"ADD"    { $logeventID = 1000 }
		"REMOVE" { $logeventID = 2000 }
	}
	switch ($result) { 
		"FAIL"   { $eventtype = [System.Diagnostics.EventLogEntryType]::Error; $logeventID += 1 }
		default  { $eventtype = [System.Diagnostics.EventLogEntryType]::Information}
	}
	$event.WriteEntry($text,$eventType,$logeventID)
}

# Log type functions
function error       ($text) { log "E" $text }
function warning     ($text) { log "W" $text } 
function debug       ($text) { log "D" $text } 
function actioned    ($text) { log "A" $text } 

# Log things to file and debug
function log ($type, $text) { 
	$output = "" + (get-date -format u).replace("Z", "") + " $tag $text"  
	if ($type -eq "A") { 
		$output | out-file $logfile -append
	}

	switch ($type) { 
		# "D" { write-debug $output } 	# cob roland: this would cause a breakpoint in inquire mode
		"D" { write-host "DEBUG: $output" } 	# roland	# NB! not using Write-Output since it would mess up function return values
		# "W" { write-warning "WARNING: $output" }  	# cob roland: Powershell adds WARNING: prefix automatically
		"W" { write-warning $output }  	# roland
		# "E" { write-error "ERROR: $output" }   	# cob roland: Powershell adds ERROR: prefix automatically
		"E" { write-error $output } 	# roland
		# "A" { write-debug $output }	# cob roland: this would cause a breakpoint in inquire mode
		"A" { write-host "ACTIONED: $output" }		# roland	# NB! not using Write-Output since it would mess up function return values
	} 
}
	 
# Get the current list of wail2ban bans
function get_jail_list {
	$fw = New-Object -ComObject hnetcfg.fwpolicy2 
	return $fw.rules | Where-Object { $_.name -match $FirewallRulePrefix } | Select name, description
}

# Confirm if rule exists.
function rule_exists ($IP) { 
	switch($BLOCK_TYPE) {
		"NETSH" { $Rule = "netsh advfirewall firewall show rule name=`"$FirewallRulePrefix $IP`"" }
		default { error "Don't have a known Block Type. $BLOCK_TYPE" }
	}
	if ($rule) { 
		$result = invoke-expression $rule
		if ($result -match "----------") {
			return "Yes"
		}  
		else { 
			return "No"
		}
	}
}

# Convert subnet Slash (e.g. 26, for /26) to netmask (e.g. 255.255.255.192)
function netmask($MaskLength) { 
	$IPAddress =  [UInt32]([Convert]::ToUInt32($(("1" * $MaskLength).PadRight(32, "0")), 2))
	$DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
	  $Remainder = $IPAddress % [Math]::Pow(256, $i)
	  ($IPAddress - $Remainder) / [Math]::Pow(256, $i)
	  $IPAddress = $Remainder
	 } )

	Return [String]::Join('.', $DottedIP)
}
  
# Check if IP is whitelisted
function whitelisted($IP) { 
	foreach ($white in $Whitelist) {
		if ($IP -eq $white) { 
			$Whitelisted = "Uniquely listed."; 
			break 
		} 

		if ($white.contains("/")) { 
			$Mask = netmask($white.Split("/")[1])
			$subnet = $white.Split("/")[0]
			if ((([net.ipaddress]$IP).Address -Band ([net.ipaddress]$Mask).Address) -eq`
				(([net.ipaddress]$subnet).Address -Band ([net.ipaddress]$Mask).Address)) { 
					$Whitelisted = "Contained in subnet $white"; break;
			}
		}
	}

	return $Whitelisted
} 

# Read in the saved file of settings. Only called on script start, such as after reboot
function pickupBanDuration { 
	if (Test-Path $BannedIPLog) { 
		get-content $BannedIPLog | %{ 
			if (!$BannedIPs.ContainsKey($_.split(" ")[0])) { $BannedIPs.Add($_.split(" ")[0], $_.split(" ")[1]) }
		}			
		debug "$BannedIPLog ban counts loaded"
	} 
	else { 
		debug "No IPs to collect from BannedIPLog" 
	}
} 

# Get the ban time for an IP, in seconds
function getBanDuration ($IP) {	
	if ($BannedIPs.ContainsKey($IP)) { 
		[int]$Setting = $BannedIPs.Get_Item($IP)
	} else { 
		$Setting = 0
		$BannedIPs.Add($IP, $Setting)
	} 
	$Setting++
	$BannedIPs.Set_Item($IP, $Setting)

	# $BanDuration =  [math]::min([math]::pow(5, $Setting) * 60, $MAX_BANDURATION)		# cob roland
	$BanDuration =  [math]::min([math]::pow($ban_pow_base, $Setting) * $MIN_BANDURATION, $MAX_BANDURATION)			# roland

	debug "IP $IP has the new setting of $setting, being $BanDuration seconds"
	if (Test-Path $BannedIPLog) { clear-content $BannedIPLog } else { New-Item $BannedIPLog -type file }
	$BannedIPs.keys | %{ "$_ " + $BannedIPs.Get_Item($_) | Out-File $BannedIPLog -Append }
	return $BanDuration
}

# Ban the IP (with checking)
function jail_lockup ($IP, $ExpireDate) { 
	$result = whitelisted($IP)
	if ($result) { 
		warning "$IP is whitelisted, except from banning. Why? $result " 
	} 
	else {
		if (!$ExpireDate) { 
			$BanDuration = getBanDuration($IP)
			$ExpireDate = (Get-Date).AddSeconds($BanDuration)
		}

		if ((rule_exists $IP) -eq "Yes") { 
			warning ("IP $IP already blocked.")
		} 
		else {
			firewall_add $IP $ExpireDate
		}
	}
}

# Unban the IP (with checking)
function jail_release ($IP) { 
	if ((rule_exists $IP) -eq "No") { 
		debug "$IP firewall listing doesn't exist. Can't remove it."
	} 
	else {  
		firewall_remove $IP
	}
}

# Add the Firewall Rule
function firewall_add ($IP, $ExpireDate) { 

	$Expire = (get-date $ExpireDate -format u).replace("Z", "")

	switch($BLOCK_TYPE) {
		"NETSH" { $Rule = "netsh advfirewall firewall add rule name=`"$FirewallRulePrefix $IP`" dir=in protocol=any action=block remoteip=$IP description=`"Expire: $Expire`"" }
		default { error "Don't have a known Block Type. $BLOCK_TYPE" }
	}

	if ($rule) { 
		$result = invoke-expression $rule
		if ($LASTEXITCODE -eq 0) {
			$BanMsg = "Action Successful: Firewall rule added for $IP, expiring on $ExpireDate"
			actioned "$BanMsg"
			event "$BanMsg" ADD OK
		} else { 
			$Message = "Action Failure: could not add firewall rule for $IP,  error: `"$result`". Return code: $LASTEXITCODE"
			error $Message 
			event $Message ADD FAIL
		}
	}

	if ($MAIL_TO) {
		Send-MailMessage -From $MAIL_TO -To $MAIL_TO -Subject ("wail2ban on " + $HostName) -Body "Firewall rule added for $IP, expiring on $ExpireDate" -Port $SMTP_PORT
	}
}

# Remove the Firewall Rule
function firewall_remove ($IP) { 
	switch($BLOCK_TYPE) {
		"NETSH" { $Rule = "netsh advfirewall firewall delete rule name=`"$FirewallRulePrefix $IP`"" }
		default { error "Don't have a known Block Type. $BLOCK_TYPE" }
	}	 
	if ($rule) { 
		$result = invoke-expression $rule
		if ($LASTEXITCODE -eq 0) {
			actioned "Action Successful: Firewall ban for $IP removed"
			event "Removed IP $IP from firewall rules"  REMOVE OK
		} else { 
			$Message = "Action Failure: could not remove firewall rule for $IP,  error: `"$result`". Return code: $LASTEXITCODE"
			error $Message
			event $Message REMOVE FAIL
		}
	}

	# if ($MAIL_TO) {
	#	Send-MailMessage -From $MAIL_TO -To $MAIL_TO -Subject ("wail2ban on " + $HostName) -Body "Firewall ban for $IP removed" -Port $SMTP_PORT
	# }
}

# Remove any expired bans
function unban_old_records {
	$jail = get_jail_list
	if ($jail) { 
		foreach ($inmate in $jail) { 		
			$IP = $inmate.Name.substring($FirewallRulePrefix.length + 1)
			$ReleaseDate = $inmate.Description.substring("Expire: ".Length)
			
			if ($([int]([datetime]$ReleaseDate - (Get-Date)).TotalSeconds) -lt 0) { 
				debug "Unban old records: $IP looks old enough $(get-date $ReleaseDate -format G)"
				jail_release $IP 
			} 
		}
	}	
}

# Convert the TimeGenerated time into Epoch
function WMIDateStringToDateTime([String] $iSt) { 
	$iSt.Trim() > $null 
	$iYear   = [Int32]::Parse($iSt.SubString( 0, 4)) 
	$iMonth  = [Int32]::Parse($iSt.SubString( 4, 2)) 
	$iDay    = [Int32]::Parse($iSt.SubString( 6, 2)) 
	$iHour   = [Int32]::Parse($iSt.SubString( 8, 2)) 
	$iMinute = [Int32]::Parse($iSt.SubString(10, 2)) 
	$iSecond = [Int32]::Parse($iSt.SubString(12, 2)) 
	$iMilliseconds = 0 	
	$iUtcOffsetMinutes = [Int32]::Parse($iSt.Substring(21, 4)) 
	if ($iUtcOffsetMinutes -ne 0) { 
		$dtkind = [DateTimeKind]::Local 
	} 
	else { 
		$dtkind = [DateTimeKind]::Utc 
	} 
	$ReturnDate =  New-Object -TypeName DateTime -ArgumentList $iYear, $iMonth, $iDay, $iHour, $iMinute, $iSecond, $iMilliseconds, $dtkind
	return (get-date $ReturnDate -UFormat "%s")
} 


# Remove recorded access attempts, by IP, or expired records if no IP provided.
function clear_attempts ($IP = 0) {
	$Removes = @()
	foreach ($a in $Entry.GetEnumerator()) { 
		if ($IP -eq 0) { 
			if ([int]$a.Value[1] + $CHECK_WINDOW -lt (get-date ((get-date).ToUniversalTime()) -UFormat "%s").replace(",", ".")) { 
				$Removes += $a.Key 
			}
		} else { 
			foreach ($a in $Entry.GetEnumerator()) { 
				if ($a.Value[0] -eq $IP) {
					$Removes += $a.Key 
				} 
			} 		
		}
	} 

	foreach ($b in $Removes) { 
		$Entry.Remove($b) 
	} 
}

################################################################################
# Process input parameters
if ($setting) { debug "wail2ban started. $setting" }

# Display current configuration.
if ($args -match "-config") { 
	write-host "`nwail2ban is currently configured to: `n ban IPs for " -nonewline
	for ($i = 1; $i -lt 5; $i++) { write-host ("" + [math]::pow($ban_pow_base, $i) + ", ") -foregroundcolor "cyan" -nonewline } 
	write-host "... $($MAX_BANDURATION/60) " -foregroundcolor "cyan" -nonewline
	write-host " minutes, `n if more than " -nonewline
	write-host $CHECK_COUNT -foregroundcolor "cyan" -nonewline
	write-host " failed attempts are found in a " -nonewline
	write-host $CHECK_WINDOW -foregroundcolor "cyan" -nonewline
	write-host " second window. `nThis process will loop every time a new record appears. "
	write-host "`nIt's currently checking:"

	foreach ($event in $CheckEvents) {  
		"- " + $Event.EventLog + " event log for event ID " + $Event.EventDescription+" (Event " + $Event.EventID + ")"
	}	

	write-host "`nAnd we're whitelisting:"

	foreach ($white in $whitelist) { 
		write-host "- $($white)" -foregroundcolor "cyan" -nonewline
	} 

	write-host "in addition to any IPs present on the network interfaces on the machine"
	exit
} 

# Release all current banned IPs
if ($args -match "-jailbreak") { 
	actioned "Jailbreak initiated by console. Removing ALL IPs currently banned"
	$EnrichmentCentre = get_jail_list
	if ($EnrichmentCentre) {		
		"`nAre you trying to escape? [chuckle]"
		"Things have changed since the last time you left the building."
		"What's going on out there will make you wish you were back in here."
		" "
		foreach ($subject in $EnrichmentCentre) { 		
			$IP = $subject.name.substring($FirewallRulePrefix.length + 1)
			firewall_remove $IP
		}
		clear-content $BannedIPLog
	} else { "`nYou can't escape, you know. `n`n(No current firewall listings to remove.)" }
	exit
}

# Show the inmates in the jail.
if ($args -match "-jail") { 
	$inmates = get_jail_list 
	if ($inmates) { 	
		"wail2ban currently banned listings: `n" 
		foreach ($a in $inmates) { 
			$IP = $a.name.substring($FirewallRulePrefix.length + 1)
			$Expire = $a.description.substring("Expire: ".length)
			"" + $IP.PadLeft(14) + " expires at $Expire"
		}		
		"`nThis is a listing of the current Windows Firewall with Advanced Security rules, starting with `""+$FirewallRulePrefix+" *`""
	} else { "There are no currrently banned IPs"}
	
	exit
} 


# Unban specific IP. Remove associated schtask, if exists. 
if ($args -match "-unban") {     
	$IP = $args[[array]::indexOf($args,"-unban") + 1] 	
	actioned "Unban IP invoked: going to unban $IP and remove from the log."
	jail_release $IP
	(gc $BannedIPLog) | ? {$_ -notmatch $IP } | sc $BannedIPLog # remove IP from ban log
	exit
}

# Display Help Message
if ($args -match "-help") { 
	help;	exit
}

# roland start
$poll = $true		# do not use wait for event since it would not detect when it is a right time to unban some IP-s in case no additional events happen from other IP-s
if ($args -match "-nopoll") {
	$poll = $false
}

$ban_pow_base = 1
if ($args -match "-recidive") {
	$ban_pow_base = 2
}
# roland end

################################################################################
# Setup for the loop

# $SinkName = "LoginAttempt"		# cob roland
$SinkName = "LoginAttempt_" + (Get-Date -UFormat %s).Replace(".", "_")		# roland: avoid error of sink already existing: "Cannot subscribe to the specified event. A subscriber with the source identifier 'LoginAttempt' already exists."

$Entry = @{}
$eventlist = "("
foreach ($a in $CheckEvents) { 
	
    # $eventlist += "(TargetInstance.EventCode=$($a.EventID) AND TargetInstance.LogFile='$($a.EventLog)') OR " 		# cob roland
    $eventlist += "(EventCode=$($a.EventID) AND LogFile='$($a.EventLog)') OR " 	# roland

	# roland start
	# NB! the key must exist there else the events are not triggered - 
	# see https://stackoverflow.com/questions/59616483/how-to-read-applications-and-services-logs-via-wmi
	# and https://stackoverflow.com/questions/2382896/how-to-collect-the-new-applications-and-services-logs-found-on-windows-7-or-wi
		
	# https://stackoverflow.com/questions/18218835/how-to-create-a-registry-entry-with-a-forward-slash-in-the-name
	$key = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\services\eventlog", $true)
	$key2 = $key.CreateSubKey($a.EventLog)	# no exception is raised if the subkey exists
	$key2.Close()
	$key.Close()
	# roland end\
}
$eventlist = $eventlist.substring(0, $eventlist.length-4) + ")"

# roland start
if ($false -and $poll) {
	$within = "WITHIN $CHECK_WINDOW"
}
else {
	$within = ""
}
# roland end

# $query = "SELECT * FROM __instanceCreationEvent $within WHERE TargetInstance ISA 'Win32_NTLogEvent' AND $eventlist" # cob roland
# $query = "SELECT * FROM __instanceCreationEvent WHERE TargetInstance ISA 'Win32_NTLogEvent'" # AND $eventlist"
$query = "SELECT * FROM Win32_NTLogEvent WHERE " + $eventlist 	# roland

actioned "wail2ban invoked"
actioned "Checking for a heap of events: "
$CheckEvents | %{ actioned " - $($_.EventLog) log event code $($_.EventID)" }
actioned "The Whitelist: $whitelist"
actioned "The Self-list: $Selflist"

pickupBanDuration


function handleEvent($TheEvent) { 	# roland

	# roland start
	$skipEvent = $false;
	if ($TheEvent.LogFile -eq "OpenSSH/Operational") {
		if (!($TheEvent.message -match "sshd: (Failed password|Connection closed by .* port .* \\[preauth\\])")) {
			$skipEvent = $true;
		}
	}
	elseif ($TheEvent.LogFile -eq "Application" -and $TheEvent.EventCode -eq 1) {
		if (!($TheEvent.message -match "tcpoverudp2: Bad magic code during")) {
			$skipEvent = $true;
		}
	}
	# roland end

	if (!$skipEvent) {	# roland
		
		select-string $RegexIP -input $TheEvent.message -AllMatches | foreach { 7
			foreach ($a in $_.matches) {
				$IP = $a.Value 		
				if ($SelfList -match $IP) { 
					debug "Whitelist of self-listed IPs! Do nothing. ($IP)" 
				}
				else {	
					$RecordID = $TheEvent.RecordNumber
					$EventDate = WMIDateStringToDateTime($TheEvent.TIMEGenerated)
					$Entry.Add($RecordID, @($IP,$EventDate))

					$IPCount = 0
					foreach ($a in $Entry.Values) { 
						if ($IP -eq $a[0]) { $IPCount++} 
					}		

					debug "$($TheEvent.LogFile) Log Event captured: ID $($RecordID), IP $IP, Event Code $($TheEvent.EventCode), Attempt #$($IPCount). "							
			
					if ($IPCount -ge $CHECK_COUNT) { 
						jail_lockup $IP		
						clear_attempts $IP
					} 
					# clear_attempts			# cob roland
					# unban_old_records		# cob roland
				}
			}
		}

	}
}

################################################################################
# Loop!

# roland start
if ($poll) {

	# $lastTime = $null
	# $lastTime = Get-Date -format "yyyyMMddHHmmss.zzzzzz"	# Get-Date -format "yyyyMMddHHmmss.zzzzzz"
	$lastTime = [System.DateTime]::UtcNow.ToString("yyyyMMddHHmmss.000000-0000")	# seems like local timezone does not work properly in the WQL

	do { #bedobedo

		if ($lastTime) {
			# $timeCondition = " AND TargetInstance.TimeGenerated > '$lastTime'"
			$timeCondition = " AND TimeGenerated > '$lastTime'"
			$orderAndLimit = "" # ORDER BY TargetInstance.TimeGenerated ASC"
			$limit = $false
		}
		else {
			$timeCondition = ""
			$orderAndLimit = "" # ORDER BY TargetInstance.TimeGenerated DESC LIMIT 1"		# NB! need to sort from newest to oldest in case of limit
			$limit = $true
		}

		# Get-WmiObject -query "SELECT * FROM Win32_NTLogEvent WHERE ((EventCode=4 and LogFile='OpenSSH/Operational') OR (EventCode=4625 and LogFile='Security') OR (EventCode=18456 and LogFile='Application'))"
		# TimeGenerated    : 20220418001857.888078-000
		# Get-WmiObject -query "SELECT * FROM Win32_NTLogEvent WHERE ((EventCode=4 and LogFile='OpenSSH/Operational') OR (EventCode=4625 and LogFile='Security') OR (EventCode=18456 and LogFile='Application')) AND TimeGenerated >= '20220424162059.000000+***'"
		# TimeGenerated >= '20220424162059.000000+***'"
		# TimeGenerated >= '20220424162059.000000-000'"

		# $new_events = Get-WmiObject -query ("SELECT * FROM Win32_NTLogEvent WHERE Logfile = 'OpenSSH/Operational'" + $timeCondition + "" + $orderAndLimit)
		$new_events = Get-WmiObject -query ($query + "" + $timeCondition + "" + $orderAndLimit)
		# $new_events = Get-WmiObject -query $query
		
		# $lastTime = $null
		if (!$limit -and $new_events) {	# NB! Reverse throws error if $new_events is empty / null
			# NB! need to sort from oldest to newest unless using limit		
			# NB! the array is reversed in place and no return value is returned from the function
			[array]::Reverse($new_events)		
		}

		foreach ($new_event in $new_events) {

			$TheEvent = $new_event		# .SourceeventArgs.NewEvent.TargetInstance

			$lastTime = $TheEvent.TimeGenerated

			if ($limit) {
				break
			}

			handleEvent($TheEvent)
		}
		
		# NB! do the unbanning outside of the loop
		clear_attempts
		unban_old_records

		Start-Sleep -Seconds $POLL_INTERVAL		# TODO: config

		# $lastTime = "20220424"
	} while ($true)
	
}
else {
# roland end

	Register-WMIEvent -Query $query -sourceidentifier $SinkName
	do { #bedobedo

		$new_event = wait-event -sourceidentifier $SinkName  
		# $TheEvent = $new_event.SourceeventArgs.NewEvent.TargetInstance 	# cob roland
		$TheEvent = $new_event	# .SourceeventArgs.NewEvent.TargetInstance		# roland

		handleEvent($TheEvent)
		
		clear_attempts			# roland
		unban_old_records		# roland
	
		Remove-event -sourceidentifier $SinkName
		
	} while ($true)

} 	# roland
