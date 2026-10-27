# One-command regression run (no game window): builds the patch + the test DLL, runs the offline host, prints PASS/FAIL.
# Needs: snap.bin / snap_truth.txt / snap_tid.txt (made once by `python take_snapshot.py` from a live game).
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$gcc = 'C:\MinGW\bin\gcc.exe'
$game = 'C:\Program Files (x86)\Steam\steamapps\common\San9WPK'
Set-Location $here

foreach ($f in 'snap.bin','snap_truth.txt','snap_tid.txt') { if (-not (Test-Path $f)) { Write-Host "missing $f - run: python take_snapshot.py"; exit 2 } }

# 1. the real patch must still build
& $gcc -shared -O2 -o "$env:TEMP\patch_check.dll" ..\src\patch.c ..\src\mydoc.def '-Wl,--enable-stdcall-fixup' -lgdi32
if ($LASTEXITCODE) { Write-Host 'BUILD FAIL: patch.c'; exit 1 }

# 2. the test DLL (includes patch.c with HOST_TEST)
& $gcc -shared -O2 -o tests.dll tests.c ..\src\mydoc.def '-Wl,--enable-stdcall-fixup' -lgdi32 -lpsapi
if ($LASTEXITCODE) { Write-Host 'BUILD FAIL: tests.c'; exit 1 }

# 3. the host folder: a copy of the (unmodified) game exe + its DLLs; tests.dll plays the role of MyDoc.dll
if (-not (Test-Path run)) { New-Item -ItemType Directory run | Out-Null }
foreach ($f in 'San9WPK.exe','koeids.dll','KOEIGrpX.dll','KoeiMPEG.dll','koeiwma.dll','SanCalc.dll','MyDoc_orig.dll') { if (-not (Test-Path "run\$f")) { Copy-Item "$game\$f" run\ } }
Copy-Item tests.dll run\MyDoc.dll -Force
foreach ($f in 'snap.bin','snap_truth.txt','snap_tid.txt') { if ((Get-Item $f).LastWriteTime -gt ((Get-Item "run\$f" -ErrorAction SilentlyContinue).LastWriteTime)) { Copy-Item $f run\ -Force } }

# 4. run (retries inside)
$out = & powershell -NoProfile -File "$here\runhost.ps1"
$out | ForEach-Object { Write-Host $_ }
$res = $out | Where-Object { $_ -match '^RESULT pass=(\d+) fail=(\d+)' } | Select-Object -Last 1
if (-not $res) { Write-Host 'NO RESULT'; exit 1 }
if ($res -match 'fail=0 ' -or $res -match 'fail=0$') { if ($res -notmatch 'aborted') { Write-Host 'ALL PASS'; exit 0 } }
Write-Host 'FAILED'; exit 1
