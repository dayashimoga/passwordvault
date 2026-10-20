Add-Type -AssemblyName System.Drawing

$sizes = @(16, 48, 128)
$outDir = "j:\rustpwdvault\apps\browser_extension\icons"
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

foreach ($s in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap $s, $s
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    
    # Background
    $bgBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(13, 17, 23))
    $g.FillRectangle($bgBrush, 0, 0, $s, $s)
    
    # Cyan Shield outline
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(0, 240, 255), [Math]::Max(1.0, [double]$s / 16.0))
    $margin = [Math]::Max(2, [int]($s / 8))
    $g.DrawEllipse($pen, $margin, $margin, $s - 2 * $margin, $s - 2 * $margin)

    # Cross / plus
    $center = $s / 2
    $inner = [Math]::Max(2, [int]($s / 4))
    $g.DrawLine($pen, [float]($center - $inner), [float]$center, [float]($center + $inner), [float]$center)
    $g.DrawLine($pen, [float]$center, [float]($center - $inner), [float]$center, [float]($center + $inner))
    
    $filePath = Join-Path $outDir "icon$s.png"
    $bmp.Save($filePath, [System.Drawing.Imaging.ImageFormat]::Png)
    $pen.Dispose()
    $bgBrush.Dispose()
    $g.Dispose()
    $bmp.Dispose()
}

Write-Host "Icons generated successfully in $outDir"
