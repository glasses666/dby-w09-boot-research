$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Docker = "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
$Base = "C:\Users\Public\dby-api32-vintf-replay-20261028-v3"
$Archive = Join-Path $Base "harness-v5.tar.gz"
$Rootfs = Join-Path $Base "rootfs"
$Evidence = Join-Path $Base "evidence"
$Container = "dby-api32-vintf-replay-20261028-v3"
$Image = "dby-offline-ubuntu:24.04.5-arm64"
$ExpectedArchiveSha256 = "d1ba9f1bf3a3354679e1cae1b7a8f9807bf418d30a8ba64ceab885f8ab0a0be2"
$ExpectedTreeSha256 = "d778490bd82874484b5b7d7828264c4ed040ec197f00d63f22750e02e8f45314"
$ExpectedQuerySha256 = "5d8bbbfdcd916ded68c4f02d9184ce09f9ab45458e903aa413a60637b940d8d4"

if (-not (Test-Path -LiteralPath $Docker -PathType Leaf)) {
    throw "Docker CLI is missing"
}
if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) {
    throw "Harness archive is missing"
}
if ((Test-Path -LiteralPath $Rootfs) -or (Test-Path -LiteralPath $Evidence)) {
    throw "Refusing to reuse an existing rootfs or evidence directory"
}

$ArchiveSha256 = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ArchiveSha256 -ne $ExpectedArchiveSha256) {
    throw "Harness archive hash mismatch"
}

New-Item -ItemType Directory -Path $Rootfs | Out-Null
New-Item -ItemType Directory -Path $Evidence | Out-Null
& tar.exe -xzf $Archive -C $Rootfs
if ($LASTEXITCODE -ne 0) {
    throw "Harness extraction failed"
}

$ManifestPath = Join-Path $Rootfs "HARNESS_MANIFEST.json"
$Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
if ($Manifest.tree.tree_sha256 -ne $ExpectedTreeSha256) {
    throw "Harness tree identity mismatch"
}
if ($Manifest.tree.symlink_count -ne 0) {
    throw "Harness unexpectedly requires host symlinks"
}
if (-not $Manifest.view_comparison.single_authorized_difference) {
    throw "Control/candidate view exceeds the authorized difference"
}
if ($Manifest.runtime.query.sha256 -ne $ExpectedQuerySha256) {
    throw "Target query identity mismatch"
}
if ($Manifest.source_derived_correction.before_sha256 -ne "3705d4036e7e87afe2c2ab800e709df105e942994d906c8b5e6d57b76438a0f7" -or
    $Manifest.source_derived_correction.after_sha256 -ne "e1709cc931677e71ac3c51257ac9e207060f95f3449b28ec5f676f992640df07" -or
    -not $Manifest.source_derived_correction.byte_length_preserved) {
    throw "Source-derived correction identity mismatch"
}

$ExpectedFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$Checks = [System.Collections.Generic.List[string]]::new()
foreach ($Record in $Manifest.tree.files) {
    $Relative = $Record.path.Replace("/", "\")
    $Path = Join-Path $Rootfs $Relative
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Harness file missing: $($Record.path)"
    }
    $Actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Actual -ne $Record.sha256) {
        throw "Harness file hash mismatch: $($Record.path)"
    }
    [void]$ExpectedFiles.Add($Record.path)
    $Checks.Add("$($Record.path): OK")
}
[void]$ExpectedFiles.Add("HARNESS_MANIFEST.json")
$RootfsPrefix = $Rootfs.TrimEnd("\") + "\"
foreach ($File in Get-ChildItem -LiteralPath $Rootfs -File -Recurse) {
    if (-not $File.FullName.StartsWith($RootfsPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Extracted file escapes rootfs: $($File.FullName)"
    }
    $Relative = $File.FullName.Substring($RootfsPrefix.Length).Replace("\", "/")
    if (-not $ExpectedFiles.Contains($Relative)) {
        throw "Unexpected extracted file: $Relative"
    }
}
$Checks | Set-Content -LiteralPath (Join-Path $Evidence "harness-input-check.log") -Encoding ascii

$Existing = & $Docker ps -a --filter "name=^/$Container$" --format "{{.Names}}"
if ($LASTEXITCODE -ne 0) {
    throw "Docker daemon is unavailable"
}
if ($Existing) {
    throw "Refusing to reuse container name $Container"
}

& $Docker image inspect $Image | Set-Content -LiteralPath (Join-Path $Evidence "image.inspect.json") -Encoding utf8
if ($LASTEXITCODE -ne 0) {
    throw "Required offline ARM64 image is unavailable"
}
& $Docker version | Set-Content -LiteralPath (Join-Path $Evidence "docker.version.txt") -Encoding utf8

$RuntimeSystem = Join-Path $Rootfs "runtime\system"
$Control = Join-Path $Rootfs "control"
$Candidate = Join-Path $Rootfs "candidate"
$Corrected = Join-Path $Rootfs "corrected"
$Runner = Join-Path $Rootfs "run-target-replay.sh"
$RunArguments = @(
    "run",
    "--name", $Container,
    "--pull", "never",
    "--platform", "linux/arm64",
    "--network", "none",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges:true",
    "--pids-limit", "64",
    "--memory", "256m",
    "--cpus", "2",
    "--mount", "type=bind,source=$RuntimeSystem,target=/system,readonly",
    "--mount", "type=bind,source=$Control,target=/control,readonly",
    "--mount", "type=bind,source=$Candidate,target=/candidate,readonly",
    "--mount", "type=bind,source=$Corrected,target=/corrected,readonly",
    "--mount", "type=bind,source=$Runner,target=/run-target-replay.sh,readonly",
    "--mount", "type=bind,source=$Evidence,target=/evidence",
    "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m",
    $Image,
    "/bin/sh", "/run-target-replay.sh"
)

& $Docker @RunArguments 1> (Join-Path $Evidence "container.stdout.txt") 2> (Join-Path $Evidence "container.stderr.txt")
$ContainerExit = $LASTEXITCODE
$ContainerExit | Set-Content -LiteralPath (Join-Path $Evidence "container.exit.txt") -Encoding ascii
& $Docker inspect $Container | Set-Content -LiteralPath (Join-Path $Evidence "container.inspect.json") -Encoding utf8
if ($ContainerExit -ne 0) {
    throw "Container execution failed with exit $ContainerExit"
}

$ControlExit = [int](Get-Content -LiteralPath (Join-Path $Evidence "control.exit.txt") -Raw).Trim()
$CandidateExit = [int](Get-Content -LiteralPath (Join-Path $Evidence "candidate.exit.txt") -Raw).Trim()
$CorrectedExit = [int](Get-Content -LiteralPath (Join-Path $Evidence "corrected.exit.txt") -Raw).Trim()
$LinkerListExit = [int](Get-Content -LiteralPath (Join-Path $Evidence "linker-list.exit.txt") -Raw).Trim()
$Architecture = (Get-Content -LiteralPath (Join-Path $Evidence "uname-m.txt") -Raw).Trim()
$ControlJson = Get-Content -LiteralPath (Join-Path $Evidence "control.json") -Raw | ConvertFrom-Json
$CandidateJson = Get-Content -LiteralPath (Join-Path $Evidence "candidate.json") -Raw | ConvertFrom-Json
$CorrectedJson = Get-Content -LiteralPath (Join-Path $Evidence "corrected.json") -Raw | ConvertFrom-Json
if ($ControlExit -ne 0) {
    throw "Control replay failed with exit $ControlExit"
}
if ($CandidateExit -notin @(0, 2)) {
    throw "Candidate replay failed outside the diagnostic contract: $CandidateExit"
}
if ($CorrectedExit -notin @(0, 2)) {
    throw "Corrected replay failed outside the diagnostic contract: $CorrectedExit"
}
if ($Architecture -ne "aarch64") {
    throw "Container architecture mismatch: $Architecture"
}
if ($ControlJson.schema -ne "dby-w09-api32-target-libvintf-replay-v1" -or
    $CandidateJson.schema -ne "dby-w09-api32-target-libvintf-replay-v1" -or
    $CorrectedJson.schema -ne "dby-w09-api32-target-libvintf-replay-v1") {
    throw "Target replay JSON schema mismatch"
}

$Summary = [ordered]@{
    schema = "dby-w09-api32-target-libvintf-windows-execution-v2"
    archive_sha256 = $ArchiveSha256
    harness_tree_sha256 = $Manifest.tree.tree_sha256
    query_sha256 = $Manifest.runtime.query.sha256
    container = $Container
    image = $Image
    architecture = $Architecture
    network = "none"
    rootfs = "read-only"
    container_exit = $ContainerExit
    linker_list_exit = $LinkerListExit
    control_exit = $ControlExit
    candidate_exit = $CandidateExit
    corrected_exit = $CorrectedExit
    device_io_performed = $false
}
$Summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $Evidence "execution-summary.json") -Encoding utf8

Write-Output "container_exit=$ContainerExit"
Write-Output "linker_list_exit=$LinkerListExit"
Write-Output "control_exit=$ControlExit"
Write-Output "candidate_exit=$CandidateExit"
Write-Output "corrected_exit=$CorrectedExit"
Write-Output "architecture=$Architecture"
