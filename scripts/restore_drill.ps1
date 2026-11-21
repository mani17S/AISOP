<#
.SYNOPSIS
    Restore drill: prove a pg_dump backup can be restored, into a THROWAWAY database, and matches its source.
.DESCRIPTION
    1. Verifies the dump against its .sha256 sidecar on the host.
    2. Copies it into the container, creates a scratch database, restores it (pg_restore, errors are captured not hidden).
    3. Compares the row count of EVERY table, the pgvector extension and embedding dimensions, and the indexes with the source database.
    4. Drops the scratch database (also on failure). The source database is only read; nothing outside the scratch database is changed.
    Writes a JSON record. Exit code 0 only if every comparison matches.
.EXAMPLE
    pwsh -File scripts\restore_drill.ps1 -Dump D:\AISOP-Backups\...\aisop_aisop_demo_x.dump -Out D:\AISOP-Backups\...\restore_drill_result.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Dump,
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$Container = "aisop-postgres",
    [string]$SourceDb = "aisop_demo",
    [string]$ScratchDb = "aisop_restore_drill",
    [string]$Username = "aisop"
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$env:MSYS_NO_PATHCONV = "1"
if ($ScratchDb -eq $SourceDb -or $ScratchDb -notmatch '^aisop_[a-z0-9_]*drill[a-z0-9_]*$') { throw "Scratch database name must contain 'drill' and differ from the source." }
if (-not (Test-Path $Dump)) { throw "Dump not found." }

function Psql([string]$Db, [string]$Sql) { (docker exec -i $Container psql -U $Username -d $Db -At -F "|" -c $Sql 2>&1 | Out-String).Trim() }
$result = [ordered]@{ dump = (Split-Path $Dump -Leaf); started = (Get-Date).ToUniversalTime().ToString("o"); checks = @() }
function Check([string]$Name, [bool]$Pass, [string]$Detail) { $script:result.checks += [ordered]@{ check = $Name; pass = $Pass; detail = $Detail }; "{0} {1} {2}" -f $(if ($Pass) { "PASS" } else { "FAIL" }), $Name, $Detail }

try {
    $side = (Get-Content "$Dump.sha256" -ErrorAction Stop | Select-Object -First 1)
    $expected = ($side -split '\s+')[0].ToLower()
    $actual = (Get-FileHash $Dump -Algorithm SHA256).Hash.ToLower()
    Check "dump matches its recorded SHA-256" ($expected -eq $actual) $actual.Substring(0, 16)

    docker exec $Container psql -U $Username -d postgres -c "DROP DATABASE IF EXISTS $ScratchDb" | Out-Null
    docker exec $Container psql -U $Username -d postgres -c "CREATE DATABASE $ScratchDb" | Out-Null
    docker cp $Dump "${Container}:/tmp/restore_drill.dump" | Out-Null
    $restoreOut = docker exec $Container pg_restore -U $Username -d $ScratchDb --exit-on-error /tmp/restore_drill.dump 2>&1 | Out-String
    Check "pg_restore finished without errors" ($LASTEXITCODE -eq 0) ($restoreOut.Trim().Substring(0, [Math]::Min(160, $restoreOut.Trim().Length)))

    $tables = (Psql $SourceDb "select tablename from pg_tables where schemaname='public' order by 1;") -split "[
]+" | Where-Object { $_ }
    $mismatch = @(); $total = 0
    foreach ($t in $tables) {
        $a = Psql $SourceDb "select count(*) from public.""$t"";"; $b = Psql $ScratchDb "select count(*) from public.""$t"";"
        $total += [int]$a
        if ($a -ne $b) { $mismatch += "$t source=$a restored=$b" }
    }
    Check "row counts equal in every table ($($tables.Count) tables, $total rows)" ($mismatch.Count -eq 0) ($mismatch -join "; ")
    Check "pgvector extension present after restore" ((Psql $ScratchDb "select count(*) from pg_extension where extname='vector';") -eq "1") ""
    $dimsA = Psql $SourceDb "select count(*), min(vector_dims(embedding)), max(vector_dims(embedding)) from knowledge_embeddings;"
    $dimsB = Psql $ScratchDb "select count(*), min(vector_dims(embedding)), max(vector_dims(embedding)) from knowledge_embeddings;"
    Check "embeddings identical in count and dimension" ($dimsA -eq $dimsB -and $dimsA -ne "") "source=$dimsA restored=$dimsB"
    $q = "select source_document, md5(embedding::text) from knowledge_embeddings order by id limit 5;"
    Check "first embedding vectors identical (md5 of the vector text)" ((Psql $SourceDb $q) -eq (Psql $ScratchDb $q)) ""
    $ixA = Psql $SourceDb "select indexname from pg_indexes where schemaname='public' order by 1;"
    $ixB = Psql $ScratchDb "select indexname from pg_indexes where schemaname='public' order by 1;"
    Check "same indexes (including HNSW)" ($ixA -eq $ixB -and $ixA -match 'hnsw') "$((($ixA -split "[
]+").Count)) indexes"
    $audA = Psql $SourceDb "select count(*), coalesce(max(created_at)::text,'') from case_audit_events;"
    $audB = Psql $ScratchDb "select count(*), coalesce(max(created_at)::text,'') from case_audit_events;"
    Check "audit trail identical (count and latest time)" ($audA -eq $audB) "source=$audA"
    $trgA = Psql $SourceDb "select count(*) from pg_trigger where not tgisinternal;"
    $trgB = Psql $ScratchDb "select count(*) from pg_trigger where not tgisinternal;"
    Check "same user triggers" ($trgA -eq $trgB) "source=$trgA restored=$trgB"
}
finally {
    docker exec $Container psql -U $Username -d postgres -c "DROP DATABASE IF EXISTS $ScratchDb" | Out-Null
    docker exec $Container rm -f /tmp/restore_drill.dump | Out-Null
    $gone = (Psql "postgres" "select count(*) from pg_database where datname='$ScratchDb';")
    Check "scratch database dropped" ($gone -eq "0") ""
    $result.finished = (Get-Date).ToUniversalTime().ToString("o")
    ($result | ConvertTo-Json -Depth 5) | Set-Content -Path $Out -Encoding UTF8
}
$failed = @($result.checks | Where-Object { -not $_.pass }).Count
"{0}/{1} checks passed" -f ($result.checks.Count - $failed), $result.checks.Count
exit $(if ($failed -eq 0) { 0 } else { 1 })
