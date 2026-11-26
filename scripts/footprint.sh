#!/usr/bin/env bash
# Samples a leukocyte daemon's memory and CPU every 10 s and prints min/avg/max.
#
#   scripts/footprint.sh <pid> [minutes]    a running daemon
#   scripts/footprint.sh --spawn [minutes]  a release build started for the run, under a temp
#                                           LEUKOCYTE_HOME with examples/personal-rules.lua as
#                                           its personal rules, in observe mode; stopped after
#
# Minutes default to 10. Per sample: RSS (`ps`; counts shared clean library pages),
# phys_footprint (`footprint`; the dirty memory the process owns, what Activity Monitor shows
# as Memory) and CPU % of one core over the 10 s window (from cumulative CPU time).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

usage() {
  echo "usage: $0 <pid|--spawn> [minutes]" >&2
  exit 2
}
[[ $# -ge 1 ]] || usage
target="$1"
minutes="${2:-10}"
[[ "$minutes" =~ ^[0-9]+$ && "$minutes" -gt 0 ]] || usage
interval=10

spawned_home=""
samples_file="$(mktemp)"
cleanup() {
  rm -f "$samples_file"
  if [[ -n "$spawned_home" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -rf "$spawned_home"
  fi
}
trap cleanup EXIT

if [[ "$target" == "--spawn" ]]; then
  cargo build --release --quiet
  spawned_home="$(mktemp -d)"
  mkdir -p "$spawned_home/config"
  cp examples/personal-rules.lua "$spawned_home/config/rules.lua"
  LEUKOCYTE_HOME="$spawned_home" target/release/leukocyte daemon \
    >"$spawned_home/daemon.log" 2>&1 &
  pid=$!
  sleep 3
  status="$(LEUKOCYTE_HOME="$spawned_home" target/release/leukocyte status)"
  if ! grep -q "mode: observe" <<<"$status"; then
    echo "the spawned daemon is not in observe mode; stopping it" >&2
    exit 1
  fi
  echo "$status"
elif [[ "$target" =~ ^[0-9]+$ ]]; then
  pid="$target"
else
  usage
fi

cpu_seconds() {
  # `ps -o time=` is [[hh:]mm:]ss.cc
  ps -o time= -p "$pid" | awk -F: '{ s = 0; for (i = 1; i <= NF; i++) s = s * 60 + $i; print s }'
}
footprint_kb() {
  footprint "$pid" 2>/dev/null | awk '/phys_footprint:/ {
    v = $2; u = $3
    if (u == "MB") v *= 1024; else if (u == "GB") v *= 1048576; else if (u == "B") v /= 1024
    printf "%d\n", v; exit }'
}

samples=$((minutes * 60 / interval))
echo "pid $pid, $(ps -A -o pid= | wc -l | tr -d ' ') processes on the machine, $samples samples every ${interval}s"
printf "%-8s %10s %18s %8s\n" "time" "rss KB" "phys_footprint KB" "cpu %"
prev_cpu="$(cpu_seconds)"
first_cpu="$prev_cpu"
for ((i = 1; i <= samples; i++)); do
  sleep "$interval"
  kill -0 "$pid" 2>/dev/null || {
    echo "pid $pid exited" >&2
    exit 1
  }
  cpu="$(cpu_seconds)"
  rss="$(ps -o rss= -p "$pid" | tr -d ' ')"
  phys="$(footprint_kb)"
  pct="$(awk -v a="$prev_cpu" -v b="$cpu" -v t="$interval" 'BEGIN { printf "%.2f", (b - a) / t * 100 }')"
  prev_cpu="$cpu"
  printf "%-8s %10s %18s %8s\n" "$((i * interval))s" "$rss" "$phys" "$pct"
  echo "$rss $phys $pct" >>"$samples_file"
done

echo
awk -v total="$(awk -v a="$first_cpu" -v b="$cpu" -v t="$((samples * interval))" 'BEGIN { printf "%.3f", (b - a) / t * 100 }')" '
  NR == 1 { for (c = 1; c <= 3; c++) { min[c] = $c; max[c] = $c } }
  { for (c = 1; c <= 3; c++) { sum[c] += $c; if ($c < min[c]) min[c] = $c; if ($c > max[c]) max[c] = $c } }
  END {
    split("rss KB,phys_footprint KB,cpu %", name, ",")
    printf "%-18s %10s %10s %10s\n", "", "min", "avg", "max"
    for (c = 1; c <= 3; c++) printf "%-18s %10.2f %10.2f %10.2f\n", name[c], min[c], sum[c] / NR, max[c]
    printf "cpu over the whole run: %s %% of one core\n", total
  }' "$samples_file"
