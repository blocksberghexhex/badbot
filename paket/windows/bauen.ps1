# Baut das Windows-Paket: badbot-collector.exe und ein MSI.
# Braucht Go und das WiX Toolset 5 samt Erweiterungen Firewall und Util:
#   dotnet tool install --global wix --version 5.0.2
#   wix extension add -g WixToolset.Firewall.wixext/5.0.2 WixToolset.Util.wixext/5.0.2
#
# Aufruf: paket\windows\bauen.ps1 -Version 1.2.3
#
# Signiert wird nur, wenn WINDOWS_SIGNIEREN auf ein Programm zeigt, das eine
# Datei signiert (Aufruf mit dem Pfad als einzigem Argument). Wie signiert
# wird, haengt vom Anbieter des Zertifikats ab; der Schluessel liegt heute
# immer in einem Hardware-Modul, nie als Datei im Bau.
param([Parameter(Mandatory = $true)][string]$Version)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..\..')

# MSI kennt nur Zahlen: v1.2.3-rc1 wird 1.2.3.
$msiVersion = ($Version.TrimStart('v') -split '[-+]')[0]
if ($msiVersion -notmatch '^\d+\.\d+\.\d+$') { throw "Version $Version ist keine x.y.z" }

New-Item -ItemType Directory -Force dist | Out-Null
$exe = 'dist\badbot-collector.exe'
$env:GOOS = 'windows'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
go build -trimpath -ldflags "-s -w -X main.Version=$Version" -o $exe .\cmd\badbot-collector
if ($LASTEXITCODE -ne 0) { throw 'go build fehlgeschlagen' }

function Signieren($datei) {
	if ($env:WINDOWS_SIGNIEREN) {
		& $env:WINDOWS_SIGNIEREN $datei
		if ($LASTEXITCODE -ne 0) { throw "Signieren von $datei fehlgeschlagen" }
	} else {
		Write-Warning "$datei nicht signiert"
	}
}

# Erst das Programm, dann das Paket: Sonst steckt im signierten MSI ein
# unsigniertes Programm.
Signieren $exe
$msi = "dist\badbot-collector-$Version-windows-x64.msi"
wix build paket\windows\badbot-collector.wxs -arch x64 `
	-ext WixToolset.Firewall.wixext -ext WixToolset.Util.wixext `
	-d "Version=$msiVersion" -d "Exe=$exe" -o $msi
if ($LASTEXITCODE -ne 0) { throw 'wix build fehlgeschlagen' }
Signieren $msi
Copy-Item $exe "dist\badbot-collector-$Version-windows-x64.exe"
Remove-Item $exe
Write-Output $msi
