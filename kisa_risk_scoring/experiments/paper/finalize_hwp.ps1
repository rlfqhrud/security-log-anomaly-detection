# build_hwpx.py가 만든 hwpx의 자리표시자를 한글 수식 개체·그림으로 바꾸고 .hwp/.hwpx/.pdf로 저장한다.
# 실행: powershell -File finalize_hwp.ps1 -In draft.hwpx -Eqs eqs.json -Fig1 fig1.png -OutBase C:\...\캡스톤_논문_v3
param([string]$In, [string]$Eqs, [string]$Fig1, [string]$OutBase, [double]$FigWidthMm = 80, [switch]$Visible)

$ErrorActionPreference = "Stop"
$eqList = Get-Content -Raw -Encoding UTF8 $Eqs | ConvertFrom-Json
$hwp = New-Object -ComObject HWPFrame.HwpObject
$hwp.XHwpWindows.Item(0).Visible = [bool]$Visible
$hwp.RegisterModule("FilePathCheckDLL", "FilePathCheckerModule") | Out-Null
"[1] open" | Write-Host
if (-not $hwp.Open($In, "HWPX", "forceopen:true")) { throw "열기 실패: $In" }

function Find-Marker([string]$marker) {
    $hwp.Run("MoveDocBegin") | Out-Null
    $f = $hwp.CreateAction("RepeatFind"); $p = $f.CreateSet(); $f.GetDefault($p)
    $p.SetItem("FindString", $marker); $p.SetItem("IgnoreMessage", 1); $p.SetItem("Direction", 0)
    $p.SetItem("FindType", 1)
    return $f.Execute($p)
}

$i = 0
foreach ($eq in $eqList) {
    $i++
    $marker = "@@E$i@@"
    if (-not (Find-Marker $marker)) { throw "자리표시자 없음: $marker" }
    $hwp.Run("Delete") | Out-Null
    $a = $hwp.CreateAction("EquationCreate"); $p = $a.CreateSet(); $a.GetDefault($p)
    $p.SetItem("String", [string]$eq.script); $p.SetItem("BaseUnit", [int]$eq.size)
    if (-not $a.Execute($p)) { throw "수식 삽입 실패: $($eq.script)" }
}

"[2] equations done" | Write-Host
if (Find-Marker "@@FIG1@@") {
    $hwp.Run("Delete") | Out-Null
    Add-Type -AssemblyName System.Drawing
    $img = [System.Drawing.Image]::FromFile($Fig1); $ratio = $img.Height / $img.Width; $img.Dispose()
    # sizeoption 1 = 지정한 크기(mm)
    $ctrl = $hwp.InsertPicture($Fig1, $true, 1, $false, $false, 0, $FigWidthMm, [math]::Round($FigWidthMm * $ratio, 1))
    if ($null -eq $ctrl) { throw "그림 삽입 실패" }
    $ps = $ctrl.Properties; $ps.SetItem("TreatAsChar", 1); $ctrl.Properties = $ps
}

"[3] figure done" | Write-Host
$hwp.SaveAs("$OutBase.hwp", "HWP", "") | Out-Null
"[4] hwp saved" | Write-Host
$hwp.SaveAs("$OutBase.hwpx", "HWPX", "") | Out-Null
"[5] hwpx saved" | Write-Host
$hwp.SaveAs("$OutBase.pdf", "PDF", "") | Out-Null
"[6] pdf saved" | Write-Host
"pages=" + $hwp.PageCount
$hwp.Clear(1); $hwp.Quit()
