param(
    [Parameter(Mandatory = $true)][string]$BaselineJar,
    [Parameter(Mandatory = $true)][string]$CandidateClasses,
    [Parameter(Mandatory = $true)][string]$DependencyClasspath,
    [Parameter(Mandatory = $true)][string]$JavaHome
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedHash = '8d42c42359160d48dd79b6d1f5b042dd8a7b3d9e37ac5a1ab6ed3a2d9f3f4e22'
$phase = 'inputs'
$baseline = $null

function Assert-BaselineHash {
    if ((Get-FileHash -LiteralPath $baseline -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) {
        throw 'Original baseline hash mismatch'
    }
}

function Invoke-Checked([string]$Executable, [string[]]$Arguments) {
    $output = @(& $Executable @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) { throw 'Java tool returned nonzero exit code' }
    return $output
}

try {
    $root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $target = [IO.Path]::GetFullPath((Join-Path $root 'target'))
    # All writes stay inside this repository's target; reject junctions/symlinks in ancestors.
    foreach ($directory in @($root, $target)) {
        $cursor = $directory
        while ($cursor) {
            if ((Test-Path -LiteralPath $cursor) -and
                ((Get-Item -LiteralPath $cursor).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'Reparse-point output ancestor is not allowed'
            }
            $cursor = [IO.Path]::GetDirectoryName($cursor)
        }
    }
    $baseline = (Resolve-Path -LiteralPath $BaselineJar).Path
    $candidate = (Resolve-Path -LiteralPath $CandidateClasses).Path.TrimEnd('\', '/')
    $jdk = (Resolve-Path -LiteralPath $JavaHome).Path
    if (-not (Test-Path -LiteralPath $baseline -PathType Leaf)) { throw 'Baseline must be a file' }
    if (-not (Test-Path -LiteralPath $candidate -PathType Container)) { throw 'Candidate must be a classes directory' }
    if (-not $candidate.StartsWith($target + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Candidate must be below repository target'
    }
    if ($baseline.StartsWith($target + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Baseline cannot be an output artifact'
    }
    if (Get-ChildItem -LiteralPath $candidate -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) {
        throw 'Candidate contains reparse points'
    }
    $cursor = $candidate
    while ($cursor -ne $root) {
        if ((Get-Item -LiteralPath $cursor).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Candidate is redirected' }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    Assert-BaselineHash
    $java = Join-Path $jdk 'bin/java.exe'
    $javac = Join-Path $jdk 'bin/javac.exe'
    $javap = Join-Path $jdk 'bin/javap.exe'
    foreach ($tool in @($java, $javac, $javap)) {
        if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw 'Incomplete JDK' }
    }
    $version = @(Invoke-Checked $java @('--version'))
    $compilerVersion = @(Invoke-Checked $javac @('--version'))
    if (($version[0] -notmatch '^(openjdk|java) 17[. ]') -or ($compilerVersion[0] -notmatch '^javac 17[. ]')) {
        throw 'JDK 17 required'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $entries = @($DependencyClasspath.Split([IO.Path]::PathSeparator))
    if ($entries.Count -eq 0) { throw 'Missing external dependencies' }
    $resolved = @()
    foreach ($entry in $entries) {
        if ([string]::IsNullOrWhiteSpace($entry)) { throw 'Empty classpath entry is forbidden' }
        $dependency = (Resolve-Path -LiteralPath $entry).Path
        if (-not $dependency.EndsWith('.jar', [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $dependency -PathType Leaf)) { throw 'Only explicit external JARs are allowed' }
        $archive = [IO.Compression.ZipFile]::OpenRead($dependency)
        try {
            if (@($archive.Entries | Where-Object {
                $_.FullName -match '(^|/)com/davidrr/security/.*\.class$' -or
                $_.FullName -eq 'LegacyPublicApiConsumer.class' -or $_.FullName -eq 'LegacySensitiveDtoConsumer.class'
            }).Count -gt 0) { throw 'Mixed or indirect classpath rejected' }
            $jarManifest = $archive.GetEntry('META-INF/MANIFEST.MF')
            if ($jarManifest) {
                $reader = [IO.StreamReader]::new($jarManifest.Open())
                try {
                    if ($reader.ReadToEnd() -match '(?im)^Class-Path:') { throw 'Indirect classpath rejected' }
                } finally { $reader.Dispose() }
            }
        } finally { $archive.Dispose() }
        $resolved += $dependency
    }
    $external = $resolved -join [IO.Path]::PathSeparator
    $manifest = Join-Path $root 'src/test/resources/compat/security-core-0.4.0-public-api.txt'
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw 'Missing original reference manifest' }
    $run = Join-Path $target ('sec001-02a-' + [Guid]::NewGuid().ToString('N'))
    $verifier = Join-Path $run 'verifier'
    $legacy = Join-Path $run 'legacy'
    New-Item -ItemType Directory -Path $verifier, $legacy -Force | Out-Null
    $phase = 'verifier compilation'
    Invoke-Checked $javac @('--release', '17', '-proc:none', '-classpath', $external, '-d', $verifier,
        (Join-Path $root 'src/test/java/com/davidrr/security/compat/PublicApiContractTest.java')) | Out-Null
    $phase = 'API/ABI comparison'
    $api = Invoke-Checked $java @('-cp', ($verifier + [IO.Path]::PathSeparator + $external),
        'com.davidrr.security.compat.PublicApiContractTest', 'verify', $baseline, $candidate, $external, $manifest)
    $phase = 'legacy compilation against original'
    Invoke-Checked $javac @('--release', '17', '-proc:none', '-classpath', ($baseline + [IO.Path]::PathSeparator + $external),
        '-d', $legacy, (Join-Path $root 'src/test/compat/LegacyPublicApiConsumer.java'),
        (Join-Path $root 'src/test/compat/LegacySensitiveDtoConsumer.java')) | Out-Null
    $runtime = $legacy + [IO.Path]::PathSeparator + $candidate + [IO.Path]::PathSeparator + $external
    $phase = 'public consumer runtime'
    $public = Invoke-Checked $java @('-cp', $runtime, 'LegacyPublicApiConsumer', $candidate, $manifest, 'public')
    $phase = 'sensitive consumer runtime'
    $sensitive = Invoke-Checked $java @('-cp', $runtime, 'LegacyPublicApiConsumer', $candidate, $manifest, 'sensitive')
    $phase = 'final baseline hash'
    Assert-BaselineHash
    # Fixed summary only: no dependency paths, machine identity or raw Java diagnostics.
    @('SEC-001-02A PASS', ('baseline.sha256=' + $expectedHash), 'jdk=17',
        'api-abi=PASS', 'legacy-public=PASS', 'legacy-sensitive=PASS', 'candidate-origins=PASS',
        'baseline-before-after=PASS') | Set-Content -LiteralPath (Join-Path $run 'summary.txt') -Encoding UTF8
    $api | Write-Output
    $public | Write-Output
    $sensitive | Write-Output
    Write-Output 'SEC-001-02A PASS: API/ABI and both old-bytecode consumers; baseline unchanged'
    exit 0
} catch {
    # Do not expose private filesystem/classpath or raw exception contents in public evidence.
    Write-Output ('SEC-001-02A FAIL during ' + $phase)
    exit 1
} finally {
    if ($baseline -and (Test-Path -LiteralPath $baseline -PathType Leaf)) {
        if ((Get-FileHash -LiteralPath $baseline -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) {
            Write-Output 'SEC-001-02A FAIL: baseline hash changed or invalid'
            exit 1
        }
    }
}
