$ErrorActionPreference = "Stop"

$llvmBin = "C:\Users\daya\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260908-ucrt-x86_64\bin"
if (Test-Path $llvmBin) {
    $env:PATH = "$llvmBin;C:\Users\daya\.cargo\bin;" + $env:PATH
} else {
    $env:PATH = "C:\Users\daya\.cargo\bin;" + $env:PATH
}
$env:CARGO_INCREMENTAL = "0"
$env:RUSTFLAGS = "-C link-arg=-static"

Push-Location "j:\rustpwdvault\core"
try {
    cargo build --release --target x86_64-pc-windows-gnullvm -p pwdvault-ffi
} finally {
    Pop-Location
}

Copy-Item "j:\rustpwdvault\core\target\x86_64-pc-windows-gnullvm\release\pwdvault_ffi.dll" -Destination "j:\rustpwdvault\apps\flutter\pwdvault_ffi.dll" -Force

# Inspect imports
& "$llvmBin\llvm-objdump.exe" -p "j:\rustpwdvault\core\target\x86_64-pc-windows-gnullvm\release\pwdvault_ffi.dll" | Select-String "DLL Name"
