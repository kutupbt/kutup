# install-cli.ps1 - install the `kutup` command-line client on Windows from a
# GitHub release, checking the archive's SHA-256 against the release's checksums.
#
#   irm https://raw.githubusercontent.com/kutupbt/kutup/master/scripts/install-cli.ps1 | iex
#
# Settings, as environment variables (set them first in the same window):
#   KUTUP_VERSION        a CLI release tag, e.g. v0.2.0 (default: the newest
#                        published one; desktop-v... tags are not CLI releases)
#   KUTUP_INSTALL_DIR    where kutup.exe goes (default %LOCALAPPDATA%\Programs\kutup)
#   KUTUP_DOWNLOAD_BASE  a mirror laid out as <base>/<tag>/<asset>
#                        (default https://github.com/kutupbt/kutup/releases/download)
#
# The install directory is added to your user PATH. No administrator rights
# are needed. Works in Windows PowerShell 5.1 and PowerShell 7.

function Install-KutupCli {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'  # Invoke-WebRequest is slow with it on
    # Windows PowerShell 5.1 may still default to TLS 1.0, which GitHub refuses.
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }

    $repo = 'kutupbt/kutup'
    $base = if ($env:KUTUP_DOWNLOAD_BASE) { $env:KUTUP_DOWNLOAD_BASE.TrimEnd('/') } else { "https://github.com/$repo/releases/download" }
    $version = $env:KUTUP_VERSION
    $installDir = $env:KUTUP_INSTALL_DIR
    if (-not $installDir) {
        if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA is not set; set KUTUP_INSTALL_DIR' }
        $installDir = Join-Path $env:LOCALAPPDATA 'Programs\kutup'
    }

    # The OS's architecture, also from a 32-bit PowerShell on 64-bit Windows.
    $cpu = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ($cpu) {
        'AMD64' { $arch = 'amd64' }
        'ARM64' { $arch = 'arm64' }
        default { throw "unsupported CPU: $cpu (x86-64 and ARM64 only)" }
    }

    # The newest published CLI release: tags vX.Y.Z, not drafts or prereleases.
    if (-not $version) {
        Write-Host 'kutup-install: finding the newest kutup CLI release...'
        try {
            $releases = Invoke-RestMethod -UseBasicParsing -Headers @{ Accept = 'application/vnd.github+json' } `
                -Uri "https://api.github.com/repos/$repo/releases?per_page=100"
        } catch {
            $status = $null
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -eq 403 -or $status -eq 429) {
                throw 'GitHub API rate limit reached for this address; wait an hour or set $env:KUTUP_VERSION (e.g. v0.2.0)'
            }
            throw "could not list releases from the GitHub API: $($_.Exception.Message); set `$env:KUTUP_VERSION to skip it"
        }
        $latest = $releases | Where-Object { $_.tag_name -match '^v[0-9]' -and -not $_.draft -and -not $_.prerelease } | Select-Object -First 1
        if (-not $latest) { throw "no published CLI release (tag vX.Y.Z) found in $repo" }
        $version = $latest.tag_name
    }
    if ($version -match '^[0-9]') { $version = "v$version" }
    if ($version -notmatch '^v[0-9]') { throw "not a CLI release tag: $version (CLI tags look like v0.2.0)" }
    $number = $version.Substring(1)

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("kutup-install-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        # Two release layouts: the Rust build (.github/workflows/release.yml)
        # names each archive after its target with a .sha256 file beside it
        # (x86-64 only; ARM64 Windows runs it emulated); v0.1.0 (the earlier
        # Go build) names them <version>_windows_<arch> with one checksums.txt.
        $sums = Join-Path $tmp 'sums'
        $rustTarget = 'x86_64-pc-windows-msvc'
        $archive = $null
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$base/$version/kutup_${version}_$rustTarget.sha256" -OutFile $sums
            $archive = "kutup_${version}_$rustTarget.zip"
        } catch {
            try {
                Invoke-WebRequest -UseBasicParsing -Uri "$base/$version/checksums.txt" -OutFile $sums
                $archive = "kutup_${number}_windows_$arch.zip"
            } catch {
                throw "release $version has no checksums for windows/$arch (is $version a published CLI release? see https://github.com/$repo/releases)"
            }
        }

        Write-Host "kutup-install: downloading kutup $version for windows/$arch..."
        $zip = Join-Path $tmp $archive
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$base/$version/$archive" -OutFile $zip
        } catch {
            throw "could not download $base/$version/$archive"
        }

        # The entry for this archive: "<sha256>  <name>" (or "*<name>").
        $want = $null
        foreach ($line in Get-Content -LiteralPath $sums) {
            $fields = $line.Trim() -split '\s+'
            if ($fields.Count -ge 2 -and $fields[1].TrimStart('*') -eq $archive) { $want = $fields[0].ToLowerInvariant(); break }
        }
        if (-not $want) { throw "the release's checksums do not list $archive; refusing to install" }
        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLowerInvariant()
        if ($got -ne $want) { throw "checksum mismatch for $archive (expected $want, got $got); refusing to install" }
        Write-Host "kutup-install: checksum verified (SHA-256 $got)"

        $unpacked = Join-Path $tmp 'x'
        Expand-Archive -LiteralPath $zip -DestinationPath $unpacked
        $exe = Get-ChildItem -LiteralPath $unpacked -Recurse -File -Filter 'kutup.exe' | Select-Object -First 1
        if (-not $exe) { throw "$archive holds no kutup.exe" }

        New-Item -ItemType Directory -Force -Path $installDir | Out-Null
        $dest = Join-Path $installDir 'kutup.exe'
        # A running kutup.exe cannot be overwritten but can be renamed aside.
        if (Test-Path -LiteralPath $dest) {
            $old = "$dest.old"
            Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
            Move-Item -LiteralPath $dest -Destination $old -Force
            Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
        }
        Copy-Item -LiteralPath $exe.FullName -Destination $dest
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    $installed = $null
    try { $installed = (& $dest version 2>$null | Select-Object -First 1) } catch { }
    if (-not $installed) { $installed = "kutup $version" }
    Write-Host "kutup-install: installed $installed to $dest"

    # On the user PATH for new windows, and in this one now.
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @()
    if ($userPath) { $entries = $userPath -split ';' | Where-Object { $_ } }
    if ($entries -notcontains $installDir) {
        [Environment]::SetEnvironmentVariable('Path', (($entries + $installDir) -join ';'), 'User')
        Write-Host "kutup-install: added $installDir to your user PATH (new terminals pick it up)"
    }
    if (($env:Path -split ';') -notcontains $installDir) { $env:Path = "$env:Path;$installDir" }
}

# A function, so an error under `irm | iex` stops the install, not the window.
try {
    Install-KutupCli
} catch {
    Write-Host "kutup-install: error: $($_.Exception.Message)" -ForegroundColor Red
}
