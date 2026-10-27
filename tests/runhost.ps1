# runs the offline test host (a copy of San9WPK.exe in run\ whose MyDoc.dll is tests.dll); the loader sometimes fails with 0xC0000142, so retry
cd $PSScriptRoot\run
for($try=1; $try -le 6; $try++){
  Remove-Item host_result.txt -ErrorAction SilentlyContinue
  $p=Start-Process -FilePath .\San9WPK.exe -WorkingDirectory . -PassThru
  if(-not $p.WaitForExit(90000)){ "timeout; killing"; $p.Kill() }
  if(Test-Path host_result.txt){ Get-Content host_result.txt | Where-Object { $_ -notmatch '^skip ' }; exit 0 }
  Start-Sleep -Seconds 4
}
"no result after retries"; exit 1
