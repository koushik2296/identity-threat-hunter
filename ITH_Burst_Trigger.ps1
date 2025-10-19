<#
  ITH Burst Trigger v5f (ASCII-safe) — “Option B”
  Goal: Keep your rules as-is. Emit realistic fields the rules expect.

  New/expanded emitters:
    - Suspicious PowerShell (AutoTriage): powershell.exe with -enc / 4104-like
    - First Seen Admin Tool on Host: PsExec / procdump on a (possibly new) host
    - MFA Bypass: okta/iam style bypass success
    - Rare Country Login: success from RU/BR (outside your normal set)
    - ASN / ISP Change: same user, back-to-back different ASNs/ISPs
    - Suspicious Test IP Ranges (Demo): 198.18.0.0/15
    - Honey Token Used: honey marker fields
    - High Risk Score (>= 90), Quantum High-Risk/QES: risk.score, threat fields

  Also includes your previous 10 scenarios (VSS Delete, Credential Stuffing, etc.)
  Emits:
    - ith.scenario (canonical name)
    - event.reason (judge-friendly explanation, shows in Security → Alerts)
    - raw.rule.name / raw.rule.explanation (handy in Discover)
    - tags[] including the rule name
#>

param(
  [ValidateSet("elastic-bulk","ingestor")] [string]$Mode = "ingestor",
  [string]$ElasticUrl = "",
  [string]$ApiKey = "",
  [string]$IndexName = "ith-events",
  [string]$IngestUrl = "",
  [int]$BurstSeconds = 60
)

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function New-CorrId { [guid]::NewGuid().ToString() }
function NowIso { (Get-Date).ToUniversalTime().ToString("o") }

function Normalize-RuleName([string]$s) {
  if (-not $s) { return $s }
  $s = $s -replace "[\u2012\u2013\u2014\u2015]", "-"  # normalize dashes
  $s = $s -replace "\s+", " "
  return $s.Trim()
}

function Merge-Tags([object]$existing, [string[]]$extras){
  $base = @()
  if ($existing -is [array]) { $base = @($existing) }
  elseif ($existing) { $base = @("$existing") }
  foreach($t in $extras){ if (-not ($base -contains $t)) { $base += $t } }
  return $base
}

$GeoPool = @(
  @{ip="198.51.100.60";  city="New York";   country="United States"; iso="US"},
  @{ip="203.0.113.77";   city="San Jose";   country="United States"; iso="US"},
  @{ip="203.0.113.150";  city="Hyderabad";  country="India";          iso="IN"},
  @{ip="198.51.100.22";  city="London";     country="United Kingdom"; iso="GB"},
  @{ip="192.0.2.45";     city="Sydney";     country="Australia";      iso="AU"}
)
$RareGeo = @(
  @{ip="198.19.24.10";  city="Moscow"; country="Russian Federation"; iso="RU"},
  @{ip="198.19.35.20";  city="Sao Paulo"; country="Brazil"; iso="BR"}
)
$ASNs = @(
  @{asn=64500; org="DemoNet A"},
  @{asn=64501; org="DemoNet B"},
  @{asn=64502; org="DemoNet C"}
)
$Hosts = @("ITH-WS-01","ITH-API-01","ITH-SQL-01","ITH-JMP-01","ITH-NEW-01","ITH-NEW-02")

function New-Doc([Parameter(Mandatory=$true)][object]$fields) {
  if (-not ($fields -is [System.Collections.IDictionary])) {
    throw "New-Doc expected hashtable, got: $($fields.GetType().FullName)"
  }
  $doc = [ordered]@{
    "@timestamp" = NowIso
    "labels"     = @{ "ith_run" = $script:ITHRunId }
  }
  foreach ($k in $fields.Keys) { $doc[$k] = $fields[$k] }
  return ($doc | ConvertTo-Json -Depth 16 -Compress)
}

function Send-Docs([string[]]$jsonDocs) {
  if ($Mode -eq "elastic-bulk") {
    if (-not $ElasticUrl -or -not $ApiKey) { throw "ElasticUrl/ApiKey required for elastic-bulk" }
    $bulkBody = ""
    foreach ($j in $jsonDocs) {
      $bulkBody += "{`"index`":{`"_index`":`"$IndexName`"}}`n$j`n"
    }
    $uri = "$ElasticUrl/$IndexName/_bulk"
    Invoke-RestMethod -Method Post -Uri $uri -Headers @{ "Authorization"="ApiKey $ApiKey"; "Content-Type"="application/x-ndjson" } -Body $bulkBody | Out-Null
  } else {
    if (-not $IngestUrl) { throw "IngestUrl required for ingestor mode" }
    foreach ($j in $jsonDocs) {
      Invoke-RestMethod -Method Post -Uri $IngestUrl -Headers @{ "Content-Type"="application/json" } -Body $j | Out-Null
    }
  }
}
function Sleep-Jitter([int]$minMs=60,[int]$maxMs=140){ Start-Sleep -Milliseconds (Get-Random -Minimum $minMs -Maximum $maxMs) }

# ===== Core scenario emitters you already had (kept) =====

function Emit-CredentialStuffing { param([string]$ruleName,[string]$explanation)
  $ruleName = Normalize-RuleName $ruleName
  $docs = @(); $user = "ith.demo"
  for ($i=0; $i -lt 16; $i++) {
    $g = $GeoPool[$i % $GeoPool.Count]; $hn = $Hosts[$i % $Hosts.Count]
    $tags = Merge-Tags @() @($ruleName,"ITH","authentication")
    $docs += New-Doc -fields ([ordered]@{
      "event"=@{"category"="authentication";"type"="start";"action"="credential_stuffing";"outcome"="failure";"reason"=$explanation}
      "ith.scenario"=$ruleName; "tags"=$tags
      "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
      "rule"=@{"name"=$ruleName;"explanation"=$explanation}
      "user"=@{"name"=$user}
      "source"=@{"ip"=$g.ip;"geo"=@{"city_name"=$g.city;"country_iso_code"=$g.iso;"country_name"=$g.country}}
      "host"=@{"name"=$hn}
      "message"="Multiple password guesses for $user"
    })
  }
  $g2=$GeoPool[0]
  $docs += New-Doc -fields ([ordered]@{
    "event"=@{"category"="authentication";"action"="login";"outcome"="success";"reason"=$explanation}
    "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","authentication","success_after_failures")
    "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
    "rule"=@{"name"=$ruleName;"explanation"=$explanation}
    "user"=@{"name"=$user}
    "source"=@{"ip"=$g2.ip;"geo"=@{"city_name"=$g2.city;"country_iso_code"=$g2.iso;"country_name"=$g2.country}}
    "message"="Successful login following many failures for $user"
  })
  Send-Docs $docs
}

function Emit-VSSDelete { param([string]$ruleName,[string]$explanation)
  $ruleName = Normalize-RuleName $ruleName
  $hn = Get-Random $Hosts; $cmd = "powershell.exe -nop -w hidden -c 'vssadmin Delete Shadows /All /Quiet'"
  $docs = @()
  $docs += New-Doc -fields ([ordered]@{
    "event"=@{"module"="windows";"category"="process";"action"="start";"outcome"="success";"reason"=$explanation}
    "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","process")
    "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
    "rule"=@{"name"=$ruleName;"explanation"=$explanation}
    "winlog"=@{"channel"="Security";"event_id"=4688}
    "process"=@{"name"="vssadmin.exe";"parent"=@{"name"="powershell.exe"};"command_line"="vssadmin Delete Shadows /All /Quiet"}
    "host"=@{"name"=$hn}
  })
  Send-Docs $docs
}

function Emit-ImpossibleTravel { param([string]$ruleName,[string]$explanation)
  $ruleName = Normalize-RuleName $ruleName
  $us=$GeoPool[0]; $in=$GeoPool[2]
  $docs=@()
  foreach($g in @($us,$in)){
    $docs += New-Doc -fields ([ordered]@{
      "event"=@{"category"="authentication";"action"="login";"outcome"="success";"reason"=$explanation}
      "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","geo")
      "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
      "rule"=@{"name"=$ruleName;"explanation"=$explanation}
      "user"=@{"name"="ith.demo"}
      "source"=@{"ip"=$g.ip;"geo"=@{"city_name"=$g.city;"country_iso_code"=$g.iso;"country_name"=$g.country}}
    })
  }
  Send-Docs $docs
}

function Emit-HoneyIdentity { param([string]$ruleName,[string]$explanation)
  $ruleName = Normalize-RuleName $ruleName
  $g = Get-Random $GeoPool
  $f=[ordered]@{
    "event"=@{"category"="authentication";"action"="honey_identity_access";"outcome"="success";"reason"=$explanation}
    "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","honey")
    "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
    "rule"=@{"name"=$ruleName;"explanation"=$explanation}
    "user"=@{"name"="ith.honey"}; "source"=@{"ip"=$g.ip}
    "labels"=@{"honey_account"=$true;"ith_run"=$script:ITHRunId}
  }
  Send-Docs @((New-Doc -fields $f))
}

function Emit-MFAFail { param([string]$ruleName,[string]$explanation)
  $ruleName = Normalize-RuleName $ruleName
  $docs=@()
  1..5 | % {
    $docs += New-Doc -fields ([ordered]@{
      "event"=@{"category"="authentication";"action"="mfa_verification_failed";"outcome"="failure";"reason"=$explanation}
      "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","mfa")
      "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
      "rule"=@{"name"=$ruleName;"explanation"=$explanation}
      "user"=@{"name"="ith.demo"}; "message"="MFA denied"
    })
  }
  Send-Docs $docs
}

function Emit-OAuthHighScopes { param([string]$ruleName,[string]$explanation)
  $ruleName = Normalize-RuleName $ruleName
  $f=[ordered]@{
    "event"=@{"category"="iam";"action"="oauth_consent";"outcome"="success";"reason"=$explanation}
    "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","oauth")
    "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
    "rule"=@{"name"=$ruleName;"explanation"=$explanation}
    "user"=@{"name"="ith.demo"}
    "oauth"=@{"app"="ith-suspicious-app";"scopes"=@("Directory.ReadWrite.All","Policy.ReadWrite.ApplicationConfiguration")}
  }
  Send-Docs @((New-Doc -fields $f))
}

function Emit-PrivEscGroupAdd { param([string]$ruleName,[string]$explanation)
  $ruleName = Normalize-RuleName $ruleName
  $docs=@()
  $docs += New-Doc -fields ([ordered]@{
    "event"=@{"category"="iam";"action"="group_membership_change";"outcome"="success";"reason"=$explanation}
    "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","privesc")
    "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
    "rule"=@{"name"=$ruleName;"explanation"=$explanation}
    "iam"=@{"changes"=@(@{"op"="add";"target.group"="Domain Admins";"principal"="ith.service"})}
    "user"=@{"name"="ith.admin"}; "group"=@{"name"="Domain Admins"}
  })
  Send-Docs $docs
}

function Emit-ServiceAnomaly { param([string]$ruleName,[string]$explanation)
  $ruleName = Normalize-RuleName $ruleName
  $f=[ordered]@{
    "event"=@{"module"="windows";"category"="process";"action"="service_stop";"outcome"="success";"reason"=$explanation}
    "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","service")
    "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
    "rule"=@{"name"=$ruleName;"explanation"=$explanation}
    "winlog"=@{"channel"="System";"event_id"=7036}
    "service_name"="MSSQLSERVER"; "service_state"="stopped"; "host"=@{"name"="ITH-SQL-01"}
  }
  Send-Docs @((New-Doc -fields $f))
}

function Emit-DigitalTwinDrift { param([string]$ruleName,[string]$explanation)
  $ruleName = Normalize-RuleName $ruleName
  $f=[ordered]@{
    "event"=@{"category"="iam";"action"="digital_twin_drift";"outcome"="detected";"reason"=$explanation}
    "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","twin")
    "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
    "rule"=@{"name"=$ruleName;"explanation"=$explanation}
    "user"=@{"name"="ith.demo"}; "raw.added_roles"=@("SQLAdmin"); "raw.removed_roles"=@("Helpdesk")
  }
  Send-Docs @((New-Doc -fields $f))
}

function Emit-QuantumGuardian { param([string]$ruleName,[string]$explanation)
  $ruleName = Normalize-RuleName $ruleName
  $f=[ordered]@{
    "event"=@{"category"="threat";"action"="quantum_signal";"outcome"="anomaly";"reason"=$explanation}
    "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","quantum")
    "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
    "rule"=@{"name"=$ruleName;"explanation"=$explanation}
    "risk"=@{"score"=95;"reason"="QES spike"}; "threat"=@{"indicator"=@{"confidence"="High"}}
  }
  Send-Docs @((New-Doc -fields $f))
}

# ===== NEW emitters to satisfy your “Option B” rules =====

function Emit-SuspiciousPowerShell { param([string]$ruleName,[string]$explanation)
  $ruleName=Normalize-RuleName $ruleName
  $hn=Get-Random $Hosts
  $enc = "powershell.exe -NoProfile -ExecutionPolicy Bypass -enc SQBFAHcAbwBuAGQAbwB3AG4A"
  $docs=@()
  $docs += New-Doc -fields ([ordered]@{
    "event"=@{"module"="sysmon";"category"="process";"action"="Process Create";"outcome"="success";"code"="1";"reason"=$explanation}
    "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","powershell","autotriage")
    "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
    "rule"=@{"name"=$ruleName;"explanation"=$explanation}
    "process"=@{"name"="powershell.exe";"command_line"=$enc;"args"=@("-enc","SQ...");"pe"=@{"original_file_name"="PowerShell.EXE"}}
    "host"=@{"name"=$hn}
  })
  $docs += New-Doc -fields ([ordered]@{
    "event"=@{"module"="windows";"category"="process";"action"="PowerShell Script Block Logging";"outcome"="success";"reason"=$explanation}
    "winlog"=@{"channel"="Microsoft-Windows-PowerShell/Operational";"event_id"=4104}
    "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","powershell")
    "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
    "rule"=@{"name"=$ruleName;"explanation"=$explanation}
    "powershell"=@{"script_block_text"="FromBase64String('SQBFA...') | IEX"}
    "host"=@{"name"=$hn}
  })
  Send-Docs $docs
}

function Emit-FirstSeenAdminTool { param([string]$ruleName,[string]$explanation)
  $ruleName=Normalize-RuleName $ruleName
  $hn = "ITH-NEW-" + (Get-Random -Minimum 100 -Maximum 999)   # simulate new host
  $tools = @(
    @{name="psexec.exe"; cmd="psexec.exe \\ITH-WS-01 cmd /c whoami /all"},
    @{name="procdump.exe"; cmd="procdump.exe -accepteula -ma lsass.exe lsass.dmp"}
  )
  $docs=@()
  foreach($t in $tools){
    $docs += New-Doc -fields ([ordered]@{
      "event"=@{"module"="sysmon";"category"="process";"action"="Process Create";"outcome"="success";"code"="1";"reason"=$explanation}
      "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","admin_tool","first_seen")
      "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
      "rule"=@{"name"=$ruleName;"explanation"=$explanation}
      "process"=@{"name"=$t.name;"command_line"=$t.cmd}
      "host"=@{"name"=$hn}
    })
  }
  Send-Docs $docs
}

function Emit-MFABypass { param([string]$ruleName,[string]$explanation)
  $ruleName=Normalize-RuleName $ruleName
  $docs=@()
  $docs += New-Doc -fields ([ordered]@{
    "event"=@{"module"="okta";"category"="authentication";"action"="user.mfa.bypass";"outcome"="success";"reason"=$explanation}
    "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","mfa","bypass")
    "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
    "rule"=@{"name"=$ruleName;"explanation"=$explanation}
    "user"=@{"name"="ith.demo"}; "source"=@{"ip"="203.0.113.50"}
  })
  Send-Docs $docs
}

function Emit-RareCountryLogin { param([string]$ruleName,[string]$explanation)
  $ruleName=Normalize-RuleName $ruleName
  $g = Get-Random $RareGeo
  $docs=@(
    New-Doc -fields ([ordered]@{
      "event"=@{"category"="authentication";"action"="login";"outcome"="success";"reason"=$explanation}
      "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","geo","rare")
      "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
      "rule"=@{"name"=$ruleName;"explanation"=$explanation}
      "user"=@{"name"="ith.demo"}
      "source"=@{"ip"=$g.ip;"geo"=@{"city_name"=$g.city;"country_iso_code"=$g.iso;"country_name"=$g.country}}
    })
  )
  Send-Docs $docs
}

function Emit-ASNChange { param([string]$ruleName,[string]$explanation)
  $ruleName=Normalize-RuleName $ruleName
  $user="ith.demo"; $docs=@()
  $pairs = @(@($ASNs[0],$ASNs[2]))
  foreach($p in $pairs){
    foreach($asn in $p){
      $docs += New-Doc -fields ([ordered]@{
        "event"=@{"category"="authentication";"action"="login";"outcome"="success";"reason"=$explanation}
        "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","asn_change")
        "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
        "rule"=@{"name"=$ruleName;"explanation"=$explanation}
        "user"=@{"name"=$user}
        "source"=@{"ip"="198.19.50." + (Get-Random -Minimum 10 -Maximum 200); "as"=@{"number"=$asn.asn; "organization"=@{"name"=$asn.org}}}
      })
    }
  }
  Send-Docs $docs
}

function Emit-TestIPRanges { param([string]$ruleName,[string]$explanation)
  $ruleName=Normalize-RuleName $ruleName
  $docs=@(
    New-Doc -fields ([ordered]@{
      "event"=@{"category"="authentication";"action"="login";"outcome"="success";"reason"=$explanation}
      "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","test_range")
      "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
      "rule"=@{"name"=$ruleName;"explanation"=$explanation}
      "user"=@{"name"="ith.demo"}
      "source"=@{"ip"="198.18.1.10"}   # inside 198.18.0.0/15
    })
  )
  Send-Docs $docs
}

function Emit-HoneyTokenUsed { param([string]$ruleName,[string]$explanation)
  $ruleName=Normalize-RuleName $ruleName
  $docs=@(
    New-Doc -fields ([ordered]@{
      "event"=@{"category"="authentication";"action"="token_used";"outcome"="success";"reason"=$explanation}
      "ith.scenario"=$ruleName; "tags"=@($ruleName,"ITH","honey","token")
      "raw.rule.name"=$ruleName; "raw.rule.explanation"=$explanation
      "rule"=@{"name"=$ruleName;"explanation"=$explanation}
      "user"=@{"name"="unknown"}
      "labels"=@{"honey_token"=$true}; "http"=@{"request"=@{"body"="token=ITH_DECOY_123"}}
      "source"=@{"ip"="203.0.113.199"}
    })
  )
  Send-Docs $docs
}

# ===== RUNNER =====
$script:ITHRunId = New-CorrId
Write-Host "`n[ ITH Burst Trigger v5f ] RunId=$($script:ITHRunId)" -ForegroundColor Cyan
Write-Host "[Mode=$Mode, Index=$IndexName, Burst=${BurstSeconds}s]" -ForegroundColor Cyan

$emitters = @(
  # Your previous 10
  @{ fn=${function:Emit-CredentialStuffing}; name="ITH - Credential Stuffing";      exp="Multiple password guesses from rotating IPs causing repeated authentication failures." },
  @{ fn=${function:Emit-VSSDelete};         name="ITH - VSS Deleted via vssadmin";  exp="Shadow copies deleted via vssadmin - ransomware precursor." },
  @{ fn=${function:Emit-ImpossibleTravel};  name="ITH - Impossible Travel";         exp="Rapid successful logins for the same user from distant geographies within short time." },
  @{ fn=${function:Emit-HoneyIdentity};     name="ITH - Honey Identity";            exp="Decoy identity used; indicates credential harvesting or lateral movement." },
  @{ fn=${function:Emit-MFAFail};           name="ITH - MFA Fail Burst";            exp="Burst of MFA challenges denied or timed out, suggesting MFA fatigue." },
  @{ fn=${function:Emit-OAuthHighScopes};   name="ITH - OAuth High Scopes";         exp="New OAuth app granted high-privileged scopes." },
  @{ fn=${function:Emit-PrivEscGroupAdd};   name="ITH - PrivEsc via GroupAdd";      exp="Account membership changed to privileged group (Domain Admins)." },
  @{ fn=${function:Emit-ServiceAnomaly};    name="ITH - Service Anomaly";           exp="Critical service stop on SQL host." },
  @{ fn=${function:Emit-DigitalTwinDrift};  name="ITH - Digital Twin Drift";        exp="Twin deviated from baseline privileges." },
  @{ fn=${function:Emit-QuantumGuardian};   name="Quantum - Guardian Signal";       exp="Entropy/nonce anomaly detected; high QES and risk score." },

  # New to fit the rules in your screenshot
  @{ fn=${function:Emit-SuspiciousPowerShell}; name="Suspicious PowerShell (AutoTriage)"; exp="PowerShell with encoded payload / script block logging triggered." },
  @{ fn=${function:Emit-FirstSeenAdminTool};   name="ITH - First Seen Admin Tool on Host"; exp="Admin tool executed on a host for the first time (PsExec/Procdump)." },
  @{ fn=${function:Emit-MFABypass};            name="ITH - MFA Bypass";                     exp="Authentication succeeded via MFA bypass event." },
  @{ fn=${function:Emit-RareCountryLogin};      name="ITH - Rare Country Login";            exp="Successful login from a rarely seen country." },
  @{ fn=${function:Emit-ASNChange};             name="ITH - ASN / ISP Change";              exp="Back-to-back logins for same user from different ASNs/ISPs." },
  @{ fn=${function:Emit-TestIPRanges};          name="ITH - Suspicious Test IP Ranges (Demo)"; exp="Login from RFC 198.18/15 test address space." },
  @{ fn=${function:Emit-HoneyTokenUsed};        name="ITH - Honey Token Used";              exp="Honey token value observed in request." }
)

$end = (Get-Date).AddSeconds($BurstSeconds); $i=0
while((Get-Date) -lt $end){
  $e=$emitters[$i % $emitters.Count]
  & $e.fn -ruleName $e.name -explanation $e.exp
  $i++; Sleep-Jitter
}
Write-Host "`nBurst completed. Correlation ID: $($script:ITHRunId)" -ForegroundColor Green
