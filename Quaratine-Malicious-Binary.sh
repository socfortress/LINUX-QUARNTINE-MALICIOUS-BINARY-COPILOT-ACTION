#!/bin/sh
set -eu

ScriptName="Quarantine-Malicious-Binary"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/logs/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart="$(date +%s)"

FilePath="${ARG1:-${1:-}}"

WriteLog() {
  Message="$1"; Level="${2:-INFO}"
  ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  line="[$ts][$Level] $Message"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >> "$LogPath" 2>/dev/null || true
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  size_kb=$(awk -v s="$(wc -c <"$LogPath")" 'BEGIN{printf "%.0f", s/1024}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  i=$((LogKeep-1))
  while [ $i -ge 1 ]; do
    src="$LogPath.$i"; dst="$LogPath.$((i+1))"
    [ -f "$src" ] && mv -f "$src" "$dst" || true
    i=$((i-1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

iso_now(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
escape_json(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

BeginNDJSON(){ TMP_AR="$(mktemp)"; }

AddRecord(){
  ts="$(iso_now)"
  orig="$1"; qpath="$2"; s_before="$3"; s_after="$4"; status="$5"; reason="$6"
  owner="${7:-}"; perms="${8:-}"; size="${9:-}"; inode="${10:-}"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"original_path":"%s","quarantine_path":"%s","sha256_before":"%s","sha256_after":"%s","status":"%s","reason":"%s","owner":"%s","perms":"%s","size_bytes":"%s","inode":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" \
    "$(escape_json "$orig")" "$(escape_json "$qpath")" \
    "$(escape_json "$s_before")" "$(escape_json "$s_after")" \
    "$(escape_json "$status")" "$(escape_json "$reason")" \
    "$(escape_json "$owner")" "$(escape_json "$perms")" \
    "$(escape_json "$size")" "$(escape_json "$inode")" >> "$TMP_AR"
}

AddStatus(){
  ts="$(iso_now)"; st="${1:-info}"; msg="$(escape_json "${2:-}")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"%s","message":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$st" "$msg" >> "$TMP_AR"
}

CommitNDJSON(){
  AR_DIR="$(dirname "$ARLog")"
  [ -d "$AR_DIR" ] || WriteLog "Directory missing: $AR_DIR (will attempt write anyway)" WARN
  if mv -f "$TMP_AR" "$ARLog" 2>/dev/null; then
    :
  else
    WriteLog "Primary write FAILED to $ARLog" WARN
    if mv -f "$TMP_AR" "$ARLog.new" 2>/dev/null; then
      WriteLog "Wrote NDJSON to $ARLog.new (fallback)" WARN
    else
      keep="/tmp/active-responses.$$.ndjson"
      cp -f "$TMP_AR" "$keep" 2>/dev/null || true
      WriteLog "Failed to write both $ARLog and $ARLog.new; saved $keep" ERROR
      rm -f "$TMP_AR" 2>/dev/null || true
      exit 1
    fi
  fi
  for p in "$ARLog" "$ARLog.new"; do
    if [ -f "$p" ]; then
      sz=$(wc -c < "$p" 2>/dev/null || echo 0)
      ino=$(ls -li "$p" 2>/dev/null | awk '{print $1}')
      head1=$(head -n1 "$p" 2>/dev/null || true)
      WriteLog "VERIFY: path=$p inode=$ino size=${sz}B first_line=${head1:-<empty>}" INFO
    fi
  done
}

RotateLog
WriteLog "=== SCRIPT START : $ScriptName (host=$HostName) ==="
if [ -z "${FilePath:-}" ]; then
  BeginNDJSON; AddStatus "error" "No file path provided (ARG1 or \$1)"; CommitNDJSON; exit 1
fi
if [ ! -e "$FilePath" ]; then
  BeginNDJSON; AddStatus "error" "File does not exist: $FilePath"; CommitNDJSON; exit 1
fi
if [ ! -f "$FilePath" ]; then
  BeginNDJSON; AddStatus "error" "Not a regular file: $FilePath"; CommitNDJSON; exit 1
fi

case "$FilePath" in
  /var/ossec/quarantine/*)
    BeginNDJSON; AddStatus "info" "Already quarantined: $FilePath"; CommitNDJSON; exit 0 ;;
esac

OWNER="$(stat -c '%U' "$FilePath" 2>/dev/null || echo unknown)"
PERMS="$(stat -c '%a' "$FilePath" 2>/dev/null || echo '-')"
SIZEB="$(stat -c '%s' "$FilePath" 2>/dev/null || wc -c < "$FilePath" 2>/dev/null || echo 0)"
INODE="$(ls -li "$FilePath" 2>/dev/null | awk '{print $1}')"
if command -v sha256sum >/dev/null 2>&1; then
  HASH_BEFORE="$(sha256sum "$FilePath" 2>/dev/null | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  HASH_BEFORE="$(shasum -a 256 "$FilePath" 2>/dev/null | awk '{print $1}')"
else
  HASH_BEFORE="sha256 unavailable"
fi
IN_USE_HINT=""
if command -v lsof >/dev/null 2>&1; then
  if lsof -- "$FilePath" 2>/dev/null | awk 'NR>1{exit 0} END{exit NR==0}' ; then
    IN_USE_HINT="(open handles detected)"
  fi
fi

QDir="/var/ossec/quarantine"
mkdir -p "$QDir" 2>/dev/null || true

BaseName="$(basename "$FilePath")"
TS="$(date -u +%Y%m%d%H%M%S)"
Quarantined="$QDir/${BaseName}.${TS}.quarantine"
if mv -f -- "$FilePath" "$Quarantined" 2>/dev/null; then
  WriteLog "Moved $FilePath -> $Quarantined $IN_USE_HINT" INFO
  chmod a-x "$Quarantined" 2>/dev/null || true
  if command -v sha256sum >/dev/null 2>&1; then
    HASH_AFTER="$(sha256sum "$Quarantined" 2>/dev/null | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    HASH_AFTER="$(shasum -a 256 "$Quarantined" 2>/dev/null | awk '{print $1}')"
  else
    HASH_AFTER="sha256 unavailable"
  fi
  STATUS="quarantined"
  REASON="File moved to quarantine$([ -n "$IN_USE_HINT" ] && printf ' %s' "$IN_USE_HINT")"
else
  WriteLog "Failed to move $FilePath to $Quarantined" ERROR
  HASH_AFTER="(n/a)"; STATUS="error"; REASON="Failed to move file (permissions/locks?)"
fi

BeginNDJSON
AddRecord "$FilePath" "$Quarantined" "$HASH_BEFORE" "$HASH_AFTER" "$STATUS" "$REASON" "$OWNER" "$PERMS" "$SIZEB" "$INODE"
CommitNDJSON

dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : duration ${dur}s ==="
