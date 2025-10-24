param(
  [string]$IngestUrl = "https://ith-ingestor-1054075376433.us-central1.run.app",
  [int]$DurationSec  = 120,
  [int]$Rps          = 60
)

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$endpoint = ($IngestUrl.TrimEnd('/')) + "/ingest"

$rules = @(
  "ITH - AI Enriched Login",
  "ITH - Credential Stuffing",
  "ITH - MFA Bypass",
  "ITH - Impossible Travel",
  "ITH - Rare Country Login",
  "ITH - ASN / ISP Change",
  "ITH - Brute Force Then Success",
  "ITH - Possible Brute-Force (source.ip + user.name)",
  "ITH Canary User Login Attempt (Failure)",
  "ITH Canary Username Touched",
  "ITH Honey Token Used",
  "ITH Honey-Identity Trap Detection",
  "ITH - Privilege Escalation",
  "ITH - VSS Deleted via vssadmin",
  "ITH - First Seen Admin Tool on Host",
  "Suspicious PowerShell (AutoTriage)",
  "ITH High Risk Score (>= 90)",
  "Quantum Guardian - High QES",
  "ITH - Quantum Guardian High-Risk Finding",
  "ITH - Quantum Adaptive Response",
  "ITH Suspicious Test IP Ranges (Demo)",
  "Ingest External Alerts (ITH)",
  "ITH - All Scenarios (Judge Demo)",
  "ITH - Suspicious Token Use",
  "ITH - Geo Velocity Spike",
  "ITH - Shared Account Usage",
  "ITH - Lateral Movement",
  "ITH - Suspicious Process Execution",
  "ITH - Anomalous Device Fingerprint",
  "ITH - New Country After Short Interval"
)

$users = "alice","bob","carol","dave","erin","frank","grace","heidi","ivy","judy","mallory","oscar","peggy","trent","victor","walter","sanity_user","demo_user","judge_user"
$geos  = "US-CA","US-NY","IN-KA","BR-SP","RU-MOW","DE-BE","IR-TE","CN-BJ","GB-LND","AU-NSW","JP-13","AE-DU"
$ips   = 1..254 | ForEach-Object { "10.0.0.$_" }

function New-RandomIP {
  $a = Get-Random -Minimum 11 -Maximum 223
  $b = Get-Random -Minimum 0  -Maximum 255
  $c = Get-Random -Minimum 0  -Maximum 255
  $d = Get-Random -Minimum 1  -Maximum 254
  "$a.$b.$c.$d"
}

function Build-EventBody([string]$ruleName) {
  $cid   = [guid]::NewGuid().ToString()
  $user  = $users | Get-Random
  $src   = $geos  | Get-Random
  do { $prev = $geos | Get-Random } while ($prev -eq $src)
  $sip   = New-RandomIP
  $dip   = $ips | Get-Random
  $action  = if ($ruleName -like "ITH - Suspicious Process*" -or $ruleName -like "Suspicious PowerShell*") { "process_start" } else { "login" }
  $outcome = if ($ruleName -like "*Failure*" -or $ruleName -like "*Brute*") { "failure" } else { "success" }

  @{
    rule_name      = $ruleName
    correlation_id = $cid
    event = @{
      "event.category" = "authentication"
      "event.action"   = $action
      "event.type"     = "start"
      "event.outcome"  = $outcome
      "user.name"      = $user
      "source.ip"      = $sip
      "destination.ip" = $dip
      "geo.src"        = $src
      "geo.prev"       = $prev
    }
  } | ConvertTo-Json -Depth 8
}

$headers = @{ "Content-Type" = "application/json" }
$stopAt  = [DateTime]::UtcNow.AddSeconds($DurationSec)
$ruleIdx = 0
$sent = 0
$fail = 0
$firstErrors = New-Object System.Collections.ArrayList

Write-Host "[ ITH Burst v10 ] Endpoint=$endpoint Duration=${DurationSec}s RPS=$Rps"

while ([DateTime]::UtcNow -lt $stopAt) {
  $tickStart = [DateTime]::UtcNow
  for ($i = 0; $i -lt $Rps; $i++) {
    $rule = $rules[$ruleIdx % $rules.Count]; $ruleIdx++
    $body = Build-EventBody $rule

    try {
      $resp = Invoke-RestMethod -Method Post -Uri $endpoint -Headers $headers -Body $body -TimeoutSec 20
      $sent++
    } catch {
      $fail++
      if ($firstErrors.Count -lt 5) {
        $msg = $_.Exception.Message
        try {
          $respStream = $_.Exception.Response.GetResponseStream()
          if ($respStream) {
            $reader = New-Object System.IO.StreamReader($respStream)
            $txt = $reader.ReadToEnd()
            if ($txt) { $msg = "$msg | $txt" }
          }
        } catch {}
        $null = $firstErrors.Add($msg)
      }
    }
  }

  $elapsedMs = ([DateTime]::UtcNow - $tickStart).TotalMilliseconds
  if ($elapsedMs -lt 1000) {
    Start-Sleep -Milliseconds ([int](1000 - $elapsedMs))
  }

  $left = [int]([Math]::Max(0, ($stopAt - [DateTime]::UtcNow).TotalSeconds))
  if ($firstErrors.Count -gt 0) {
    Write-Host ("Sent={0} Fail={1} TimeLeft={2}s  FirstErrors=[{3}]" -f $sent, $fail, $left, ($firstErrors -join " | "))
  } else {
    Write-Host ("Sent={0} Fail={1} TimeLeft={2}s" -f $sent, $fail, $left)
  }
}

Write-Host ("DONE Sent={0} Fail={1}" -f $sent, $fail)
