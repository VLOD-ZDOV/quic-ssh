# qsh installer for Windows (the client; the server, qshd, needs a Unix system):
#   irm https://github.com/VLOD-ZDOV/quic-ssh/releases/latest/download/install.ps1 | iex
# QSH_VERSION=v1.0.2 picks a release (default: the latest), QSH_BIN_DIR the install directory.
& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $repo = 'VLOD-ZDOV/quic-ssh'
    $name = 'qsh-x86_64-windows'
    $dir = if ($env:QSH_BIN_DIR) { $env:QSH_BIN_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\qsh' }
    $exe = Join-Path $dir 'qsh.exe'

    if ($env:QSH_VERSION) {
        $tag = $env:QSH_VERSION
        $url = "https://github.com/$repo/releases/download/$tag"
    } else {
        # releases/latest redirects to .../tag/<latest tag>.
        $tag = try {
            $req = [Net.WebRequest]::Create("https://github.com/$repo/releases/latest")
            $req.Method = 'HEAD'
            $resp = $req.GetResponse()
            $resp.ResponseUri.Segments[-1]
            $resp.Close()
        } catch { $null }
        $url = "https://github.com/$repo/releases/latest/download"
    }
    if ($tag -and (Test-Path $exe)) {
        # qsh prints its version on stderr, like ssh -V, which Windows PowerShell turns into errors.
        $psi = New-Object Diagnostics.ProcessStartInfo $exe, '--version'
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $p = [Diagnostics.Process]::Start($psi)
        $out = $p.StandardError.ReadToEnd() + $p.StandardOutput.ReadToEnd()
        $p.WaitForExit()
        $have = if ($out -match 'qsh (\d[\w.-]*)') { $Matches[1] } else { $null }
        if ($have -and "v$have" -eq $tag) {
            Write-Host "qsh $have is up to date"
            return
        }
    }

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory $tmp | Out-Null
    try {
        Write-Host "Downloading $name.zip"
        Invoke-WebRequest "$url/$name.zip" -OutFile "$tmp\$name.zip" -UseBasicParsing
        Invoke-WebRequest "$url/SHA256SUMS" -OutFile "$tmp\SHA256SUMS" -UseBasicParsing
        $line = Get-Content "$tmp\SHA256SUMS" | Where-Object { $_ -match "\s\*?$name\.zip$" } | Select-Object -First 1
        if (-not $line) { throw "$name.zip is not in SHA256SUMS" }
        $want = ($line -split '\s+')[0]
        if ((Get-FileHash "$tmp\$name.zip" -Algorithm SHA256).Hash -ne $want) { throw "checksum mismatch for $name.zip" }
        Expand-Archive "$tmp\$name.zip" $tmp

        New-Item -ItemType Directory -Force $dir | Out-Null
        # A running qsh.exe (qsh update) cannot be overwritten, but it can be renamed.
        Remove-Item "$exe.old" -Force -ErrorAction SilentlyContinue
        if (Test-Path $exe) { Rename-Item $exe 'qsh.exe.old' }
        Copy-Item "$tmp\$name\qsh.exe" $exe
        Write-Host "Installed qsh to $dir"

        $path = [Environment]::GetEnvironmentVariable('Path', 'User')
        if (-not (($path -split ';') -contains $dir)) {
            [Environment]::SetEnvironmentVariable('Path', $(if ($path) { "$path;$dir" } else { $dir }), 'User')
            $env:Path = "$env:Path;$dir"
            Write-Host "Added $dir to your PATH; open a new terminal to use it."
        }
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}
