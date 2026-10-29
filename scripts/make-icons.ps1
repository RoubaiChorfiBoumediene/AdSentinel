# Génère les icônes PNG de l'extension (bouclier + œil) dans icons/.
# Usage : powershell -ExecutionPolicy Bypass -File scripts/make-icons.ps1
Add-Type -AssemblyName System.Drawing

$outDir = Join-Path $PSScriptRoot '..\icons'
New-Item -ItemType Directory -Force $outDir | Out-Null

function New-Icon([int]$size) {
  $s = 512  # dessin en haute résolution, puis réduction
  $bmp = New-Object System.Drawing.Bitmap $s, $s
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = 'AntiAlias'
  $g.Clear([System.Drawing.Color]::Transparent)

  # Bouclier
  $shield = New-Object System.Drawing.Drawing2D.GraphicsPath
  $shield.AddBezier(256, 24, 330, 70, 400, 80, 470, 80)
  $shield.AddBezier(470, 80, 470, 300, 400, 420, 256, 492)
  $shield.AddBezier(256, 492, 112, 420, 42, 300, 42, 80)
  $shield.AddBezier(42, 80, 112, 80, 182, 70, 256, 24)
  $shield.CloseFigure()
  $rect = New-Object System.Drawing.Rectangle 0, 0, $s, $s
  $fill = New-Object System.Drawing.Drawing2D.LinearGradientBrush $rect, `
    ([System.Drawing.Color]::FromArgb(255, 37, 99, 235)), ([System.Drawing.Color]::FromArgb(255, 30, 41, 99)), 90
  $g.FillPath($fill, $shield)

  # Œil
  $eye = New-Object System.Drawing.Drawing2D.GraphicsPath
  $eye.AddBezier(116, 250, 180, 160, 332, 160, 396, 250)
  $eye.AddBezier(396, 250, 332, 340, 180, 340, 116, 250)
  $eye.CloseFigure()
  $g.FillPath([System.Drawing.Brushes]::White, $eye)
  $pupil = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 220, 38, 38))
  $g.FillEllipse($pupil, 206, 200, 100, 100)
  $g.FillEllipse([System.Drawing.Brushes]::White, 236, 222, 28, 28)

  $out = New-Object System.Drawing.Bitmap $size, $size
  $g2 = [System.Drawing.Graphics]::FromImage($out)
  $g2.InterpolationMode = 'HighQualityBicubic'
  $g2.SmoothingMode = 'AntiAlias'
  $g2.DrawImage($bmp, 0, 0, $size, $size)
  $path = Join-Path $outDir "icon$size.png"
  $out.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
  $g2.Dispose(); $out.Dispose(); $g.Dispose(); $bmp.Dispose()
  Write-Output "icons/icon$size.png"
}

foreach ($size in 16, 32, 48, 128) { New-Icon $size }
