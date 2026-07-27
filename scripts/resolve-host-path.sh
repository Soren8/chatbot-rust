#!/usr/bin/env bash
# Map a path visible in this environment to the path the *host* Docker daemon
# should use for bind mounts (docker-outside-of-docker / agent sandboxes).
#
# Usage: resolve-host-path.sh [PATH]
# Prints one absolute host path on stdout.
#
# Resolution order:
#   1. docker inspect of this container (match hostname or cgroup id) — preferred
#   2. /proc/self/mountinfo fallback
#   3. absolute path of PATH (host-native / unmapped)
#
# Never hardcodes machine-specific directories; safe for any clone location.
set -euo pipefail

target="${1:-.}"
if [[ ! -e "$target" ]]; then
  echo "resolve-host-path: path does not exist: $target" >&2
  exit 1
fi
abs="$(cd "$target" && pwd -P)"

# --- docker inspect of the current container ---
map_via_docker_inspect() {
  command -v docker >/dev/null 2>&1 || return 1
  docker info >/dev/null 2>&1 || return 1

  local cid=""
  if docker inspect "$(hostname)" >/dev/null 2>&1; then
    cid="$(hostname)"
  else
    local cg
    cg="$(cat /proc/self/cgroup 2>/dev/null || true)"
    if [[ "$cg" =~ ([0-9a-f]{64}) ]]; then
      cid="${BASH_REMATCH[1]}"
    elif [[ "$cg" =~ (docker|containerd)-([0-9a-f]{12,}) ]]; then
      cid="${BASH_REMATCH[2]}"
    fi
  fi
  [[ -n "$cid" ]] || return 1

  local best_dest="" best_src="" src dest
  while read -r src dest; do
    [[ -n "${dest:-}" && -n "${src:-}" ]] || continue
    if [[ "$abs" == "$dest" || "$abs" == "$dest"/* ]]; then
      if [[ ${#dest} -gt ${#best_dest} ]]; then
        best_dest="$dest"
        best_src="$src"
      fi
    fi
  done < <(docker inspect -f '{{range .Mounts}}{{println .Source .Destination}}{{end}}' "$cid" 2>/dev/null)

  [[ -n "$best_src" ]] || return 1
  local rel="${abs#"$best_dest"}"
  rel="${rel#/}"
  if [[ -n "$rel" ]]; then
    printf '%s\n' "${best_src%/}/${rel}"
  else
    printf '%s\n' "$best_src"
  fi
}

# --- mountinfo fallback (no docker CLI needed for the mapping step) ---
# Format: id parent major:minor root mountpoint opts [optfields] - fstype source super
map_via_mountinfo() {
  [[ -r /proc/self/mountinfo ]] || return 1

  local best_mp="" best_root="" line root mp rest
  while IFS= read -r line; do
    # Split optional fields at " - "
    case "$line" in
      *" - "*) rest="${line%% - *}" ;;
      *) continue ;;
    esac
    # root is field 4, mountpoint is field 5 (paths without spaces in practice)
    root="$(printf '%s\n' "$rest" | awk '{print $4}')"
    mp="$(printf '%s\n' "$rest" | awk '{print $5}')"
    [[ -n "$mp" && -n "$root" ]] || continue
    if [[ "$abs" == "$mp" || "$abs" == "$mp"/* ]]; then
      if [[ ${#mp} -gt ${#best_mp} ]]; then
        best_mp="$mp"
        best_root="$root"
      fi
    fi
  done < /proc/self/mountinfo

  [[ -n "$best_mp" && -n "$best_root" ]] || return 1

  # Strip common btrfs subvolume prefixes from root (e.g. /@rootfs/home/... → /home/...)
  local host_base="$best_root"
  case "$host_base" in
    /@rootfs/*) host_base="${host_base#/@rootfs}" ;;
    /@/*) host_base="${host_base#/@}" ;;
  esac
  # If still not absolute after strip, treat root as opaque and give up
  [[ "$host_base" == /* ]] || return 1

  local rel="${abs#"$best_mp"}"
  rel="${rel#/}"
  if [[ -n "$rel" ]]; then
    printf '%s\n' "${host_base%/}/${rel}"
  else
    printf '%s\n' "$host_base"
  fi
}

if mapped="$(map_via_docker_inspect 2>/dev/null)" && [[ -n "$mapped" ]]; then
  printf '%s\n' "$mapped"
  exit 0
fi
if mapped="$(map_via_mountinfo 2>/dev/null)" && [[ -n "$mapped" ]]; then
  printf '%s\n' "$mapped"
  exit 0
fi

# Host-native (or unmapped): absolute path is fine for the local daemon
printf '%s\n' "$abs"
