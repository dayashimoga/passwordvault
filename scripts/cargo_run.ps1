$llvmBin = "C:\Users\daya\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260908-ucrt-x86_64\bin"
if (Test-Path $llvmBin) {
    $env:PATH = "$llvmBin;C:\Users\daya\.cargo\bin;" + $env:PATH
} else {
    $env:PATH = "C:\Users\daya\.cargo\bin;" + $env:PATH
}
$env:CARGO_INCREMENTAL = "0"

Push-Location "j:\rustpwdvault\core"
try {
    & cargo $args
} finally {
    Pop-Location
}
