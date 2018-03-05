
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", '', Scope = "Function", Target = "*")]

# Import the osquery utility functions
$utils = Join-Path $(Get-Location) 'tools\provision\chocolatey\osquery_utils.ps1'
if (-not (Test-Path $utils)) {
  $msg = '[-] This script must be run from osquery source root.'
  Write-Host $msg -ForegroundColor Red
  exit
}
. $utils


function Prepare-Build() {
  param(
    [string] $packsPath = $(Join-Path $(Get-Location) 'packs'),
    [string] $certsPath = '',
    [string] $shell = 'build\windows10\osquery\Release\osqueryi.exe',
    [string] $daemon = 'build\windows10\osquery\Release\osqueryd.exe',
    [string] $version = '0.0.0',
    [array] $Extras = @()
  )

  $workingDir = Get-Location
  $outdir = $(Join-Path $(Get-Location) 'out')

  if (Test-Path $outdir) {
      Remove-Item -Recurse -Force $outdir
      New-Item -ItemType directory -Path $outdir
  }

  $zipfile = $(Join-Path $workingDir osquery.zip)
  if (Test-Path $zipfile) {
      Remove-Item -Force $zipfile
  }

  if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host '[-] Powershell 5.0 or great is required for this script.' `
      -ForegroundColor Red
    exit
  }

  if (-not (Test-Path (Join-Path (Get-location).Path 'tools\make-win64-binaries.bat'))) {
    Write-Host '[-] This script must be run from the osquery repo root.' `
      -ForegroundColor Red
    exit
  }

  # bundle default certs
  if (-not (Test-Path $certsPath)) {
    $msg = '[*] Did not find openssl certs.pem, skipping.'
    Write-Host $msg -ForegroundColor Yellow
  }

  # bundle default packs
  if (-not (Test-Path $packsPath)) {
    $msg = '[*] Did not find example packs, skipping.'
    Write-Host $msg -ForegroundColor Yellow
  }

  # Working directory and output of files will be in `build/msi`
  $buildPath = Join-Path $(Get-OsqueryBuildPath) 'msi'
  if (-not (Test-Path $buildPath)) {
    New-Item -Force -ItemType Directory -Path $buildPath
  }
  Set-Location $buildPath

  Copy-Item -Recurse -Force $certsPath $(Join-Path $outdir 'certs')
  Copy-Item -Recurse -Force $packsPath $(Join-Path $outdir 'packs')
  Copy-Item -Force $shell $outdir
  Copy-Item -Force $daemon $outdir
  Copy-Item -Force "$scriptPath\tools\manage-osqueryd.ps1" $outdir

  $lic = Join-Path $scriptPath 'LICENSE'
  Copy-Item -Force $lic $(Join-Path $outdir 'LICENSE.txt')

  $verification = Join-Path $outdir 'VERIFICATION.txt'
  $verMessage =
  @'
To verify the osquery binaries are valid and not corrupted, one can run one of the following:

C:\Users\> Get-FileHash -Algorithm SHA256 .\build\windows10\osquery\Release\osqueryd.exe
C:\Users\> Get-FileHash -Algorithm SHA1 .\build\windows10\osquery\Release\osqueryd.exe
C:\Users\> Get-FileHash -Algorithm MD5 .\build\windows10\osquery\Release\osqueryd.exe

And verify that the digests match one of the below values:

'@
  $verMessage += 'SHA256: ' + (Get-FileHash -Algorithm SHA256 $daemon).Hash + "`r`n"
  $verMessage += 'SHA1: ' + (Get-FileHash -Algorithm SHA1 $daemon).Hash + "`r`n"
  $verMessage += 'MD5: ' + (Get-FileHash -Algorithm MD5 $daemon).Hash + "`r`n"

  $verMessage | Out-File -Encoding "UTF8" $verification

  $7z = (Get-Command '7z.exe').Source
  # This bundles up all of the files we distribute.
  $7zArgs = @(
    'a',
    "$zipfile",
    "$outdir\*"
  )
  Start-OsqueryProcess $7z $7zArgs

  Set-Location $workingDir
}


function Main() {

  $scriptPath = Get-Location
  $buildPath = Join-Path $scriptPath 'build\windows10\osquery\Release'
  $daemon = Join-Path $buildPath 'osqueryd.exe'
  $shell = Join-Path $buildPath 'osqueryi.exe'

  if ((-not (Test-Path $shell)) -or (-not (Test-Path $daemon))) {
    $msg = '[-] Did not find Release binaries, check build script output.'
    Write-Host $msg -ForegroundColor Red
    exit
  }

  $git = Get-Command 'git'
  $gitArgs = @(
    'describe',
    '--tags'
  )
  $version = $(Start-OsqueryProcess $git $gitArgs).stdout
  $latest = $version.split('-')[0]
  # If split len is greater than 1, this is a pre-release. Chocolatey is
  # particular about the format of the version for pre-releases.
  if ($version.split('-').length -eq 3) {
    $version = $latest + '-' + $version.split('-')[2]
  }
  # Strip off potential carriage return or newline from version string
  $version = $version.trim()


    Write-Host '[*] Preparing package blob' -ForegroundColor Cyan
    $chocoPath = [System.Environment]::GetEnvironmentVariable('ChocolateyInstall', 'Machine')
    $certs = $(Join-Path $chocoPath 'lib\openssl\local\certs')
    if ($ConfigFilePath -eq '') {
      $ConfigFilePath = $(Join-Path (Get-Location) 'tools\deployment\osquery.example.conf')
    }
    Prepare-Build -shell $shell `
                   -daemon $daemon `
                   -certsPath $certs `
                   -version $latest `
                   -extras $Extras

}

$null = Main
