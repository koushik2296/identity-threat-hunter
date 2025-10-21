param(
  [Parameter(Mandatory=$true)][string]$IngestUrl,
  [int]$Seconds = 60
)

Write-Host "[ ITH Burst ] Target=$IngestUrl, Duration=$Seconds s"

$scenarios = @(
  @{ name="impossible_travel"; score=95; outcome="success" },
  @{ name="mfa_bypass"; score=90; outcome="success" },
  @{ name="brute_force_then_success"; score=88; outcome="success" },
  @{ name="rare_country"; score=80; outcome="success" },
  @{ name="asn_change"; score=85; outcome="success" },
  @{ name="credential_stuffing"; score=92; outcome="failure" },
  @{ name="honey_identity"; score=99; outcome="failure" }
)

$end = (Get-Date).AddSeconds($Seconds)
$i = 0
while((Get-Date) -lt $end){
  foreach($s in $scenarios){
    $doc = @{
      "@timestamp" = (Get-Date).ToUniversalTime().ToString("o")
      event       = @{ category="authentication"; action=$s.name; outcome=$s.outcome; kind="event" }
      user        = @{ name=("user{0}" -f (Get-Random -Minimum 1000 -Maximum 9999)) }
      source      = @{ ip=("198.51.100.{0}" -f (Get-Random -Minimum 1 -Maximum 254)) }
      risk        = @{ score=$s.score; reason=("Synthetic test: {0}" -f $s.name) }
    } | ConvertTo-Json -Depth 5
    try {
      Invoke-RestMethod -Method POST -Uri $IngestUrl -ContentType "application/json" -Body $doc | Out-Null
    } catch {
      Write-Warning ("POST failed: {0}" -f $_.Exception.Message)
    }
    Start-Sleep -Milliseconds 150
    $i++
  }
}
Write-Host ("[ ITH Burst ] Sent ~{0} events" -f $i)