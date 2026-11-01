#!/usr/bin/env bash
#
# Runs a measured pair of CLI trial runs between two machines: run A, then
# run B in the other direction, with tools/cli-trials.js. The commands are
# the ones docs/TESTING.md lays out ("A measured rate"), with everything
# both machines must agree on derived from two values they are both given:
# the start time and the network config's name.
#
#   machine 1: receiver in run A, sender in run B
#   machine 2: sender in run A, receiver in run B
#
# Start it on either machine first, without --start. It picks a start
# time about 5 minutes out and prints the command for the other machine,
# with that time in it. Then run that command on the other machine.
#
# Seeds and file names come from the start time, formatted in UTC, and the
# config name, never from the local clock, so the two machines name
# everything the same even if their clocks or time zones differ. Several
# runs on one config in one day get different names.
#
# Runs on macOS's bash 3.2 as well as Linux.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRIVER="$REPO_ROOT/tools/cli-trials.js"
GENERATOR="$REPO_ROOT/engine/scratch-trials-environment.js"

usage () {
  cat <<'EOF'
Usage: tools/cli-trials-run.sh --machine <1|2> --config <name> [options] [-- <driver args>...]

Required:
  --machine <1|2>      1 receives in run A and sends in run B; 2 does the opposite
  --config <name>      the network pair, e.g. starlink-cgnat-to-comcast-home-router.
                       Letters, digits, '.', '_', and '-'. Must match on both machines.

Options:
  --start <epoch>      the first slot, in Unix seconds. Leave it out on the machine
                       you start first: one about 5 minutes out is picked and printed,
                       with the command to run on the other machine.
  --trials <n>         trials per run (default 20). Must match on both machines.
  --slot <s>           seconds per trial (default 135). Must match on both machines.
  --gap <s>            seconds between run A's last slot and run B's first
                       (default 300). Must match on both machines.
  --mode <dir|stdout>  how this machine receives in its receiving run (default dir)
  --file <path>        what this machine sends (default /tmp/test.bin). Created,
                       10 MiB of random bytes, if it does not exist.
  --run-root <dir>     where run directories go (default ~/trials). Keep it outside
                       the repository, or under its gitignored trials/.
  --note <text>        what this machine cannot detect about its network, e.g.
                       "eero firewall on, default rules". Repeatable.
  --lookup-isp         record this machine's ISP; sends its public address to a DNS lookup
  --plan               print the schedule and the file names, and exit
  -h, --help           this text

Anything after -- is passed to tools/cli-trials.js as is.
EOF
}

die () {
  echo "cli-trials-run: $*" >&2
  exit 1
}

MACHINE=""
CONFIG=""
START=""
TRIALS=20
SLOT=135
GAP=300
MODE=dir
FILE=/tmp/test.bin
RUN_ROOT="$HOME/trials"
LOOKUP_ISP=0
PLAN_ONLY=0
NOTES=()
EXTRA=()

while [ $# -gt 0 ]; do
  case "$1" in
    --machine) MACHINE="${2:-}"; shift 2 ;;
    --config) CONFIG="${2:-}"; shift 2 ;;
    --start) START="${2:-}"; shift 2 ;;
    --trials) TRIALS="${2:-}"; shift 2 ;;
    --slot) SLOT="${2:-}"; shift 2 ;;
    --gap) GAP="${2:-}"; shift 2 ;;
    --mode) MODE="${2:-}"; shift 2 ;;
    --file) FILE="${2:-}"; shift 2 ;;
    --run-root) RUN_ROOT="${2:-}"; shift 2 ;;
    --note) [ $# -ge 2 ] || die "--note needs a value"; NOTES+=(--note "$2"); shift 2 ;;
    --lookup-isp) LOOKUP_ISP=1; shift ;;
    --plan) PLAN_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; EXTRA=("$@"); break ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

# --- checks ------------------------------------------------------------------

[ "$MACHINE" = 1 ] || [ "$MACHINE" = 2 ] || { usage >&2; die "--machine must be 1 or 2"; }
[ -n "$CONFIG" ] || { usage >&2; die "--config is required, and must match on both machines"; }
case "$CONFIG" in
  *[!A-Za-z0-9._-]*) die "--config may hold only letters, digits, '.', '_', and '-': it becomes a seed and a directory name" ;;
esac
case "$TRIALS" in ''|*[!0-9]*) die "--trials must be a whole number" ;; esac
case "$SLOT" in ''|*[!0-9]*) die "--slot must be a whole number of seconds" ;; esac
case "$GAP" in ''|*[!0-9]*) die "--gap must be a whole number of seconds" ;; esac
[ "$TRIALS" -ge 1 ] || die "--trials must be at least 1"
[ "$MODE" = dir ] || [ "$MODE" = stdout ] || die "--mode must be dir or stdout"
command -v node > /dev/null || die "node is not on PATH"

NOW=$(date +%s)
PICKED=0
if [ -z "$START" ]; then
  START=$((NOW + 300))
  PICKED=1
fi
case "$START" in ''|*[!0-9]*) die "--start must be Unix seconds, e.g. $((NOW + 300))" ;; esac
# Both machines have to be running before the first slot opens. 15 s is
# the least that can work; 5 minutes leaves time to start the other one.
if [ "$START" -lt $((NOW + 15)) ]; then
  die "--start $START is $((START - NOW)) s from now, too soon to start both machines: use one about 5 minutes out (e.g. $((NOW + 300)))"
fi

# Formatted by node, in UTC, so macOS and Linux agree without BSD/GNU
# `date` differences and without either machine's time zone.
fmt () {
  node -e 'const d = new Date(Number(process.argv[1]) * 1000); const p = (n) => String(n).padStart(2, "0");
    const kind = process.argv[2];
    if (kind === "stamp") console.log(`${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}T${p(d.getUTCHours())}${p(d.getUTCMinutes())}Z`);
    else console.log(`${d.toLocaleString()} local, ${d.toISOString().replace(".000", "")}`)' "$1" "$2"
}

STAMP=$(fmt "$START" stamp)
# Run B starts once run A's last slot is over, plus a margin (--gap,
# 5 minutes by default) for a run that started late. Both machines
# compute the same value.
START_B=$((START + TRIALS * SLOT + GAP))
RUN_DIR="$RUN_ROOT/$STAMP/$CONFIG"

if [ "$MACHINE" = 1 ]; then
  ROLE_A=receiver; ROLE_B=sender; SIDE_A=rx; SIDE_B=tx
else
  ROLE_A=sender; ROLE_B=receiver; SIDE_A=tx; SIDE_B=rx
fi
OUT_A="$RUN_DIR/$STAMP-cli-a-$SIDE_A"
OUT_B="$RUN_DIR/$STAMP-cli-b-$SIDE_B"
OTHER=$((3 - MACHINE))
END=$((START_B + TRIALS * SLOT))

# The command for the other machine: everything that must match, and none
# of this machine's own options (its notes, its file, its mode).
OTHER_CMD="tools/cli-trials-run.sh --machine $OTHER --config $CONFIG --start $START"
[ "$TRIALS" = 20 ] || OTHER_CMD="$OTHER_CMD --trials $TRIALS"
[ "$SLOT" = 135 ] || OTHER_CMD="$OTHER_CMD --slot $SLOT"
[ "$GAP" = 300 ] || OTHER_CMD="$OTHER_CMD --gap $GAP"

COMMIT=$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD 2> /dev/null || echo unknown)
DIRTY=""
if [ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no 2> /dev/null)" ]; then
  DIRTY=" (UNCOMMITTED CHANGES: the two machines may not be running the same code)"
fi

cat <<EOF

=================================================================
  START:  $START     <-- the same on both machines
          $(fmt "$START" human)
  CONFIG: $CONFIG
=================================================================

EOF
if [ "$PICKED" = 1 ]; then
  cat <<EOF
  Picked a start time. Now run this on machine $OTHER, before
  $(fmt "$START" human):

    $OTHER_CMD

EOF
fi
cat <<EOF
  This is machine $MACHINE.
    run A:  $ROLE_A, $TRIALS trials from $(fmt "$START" human)
    run B:  $ROLE_B, $TRIALS trials from $(fmt "$START_B" human)
    done by about $(fmt "$END" human)
  slot $SLOT s; receiving mode $MODE; commit $COMMIT$DIRTY

  output: $RUN_DIR/
    $(basename "$OUT_A").json, .log
    $(basename "$OUT_B").json, .log

EOF

[ "$PLAN_ONLY" = 1 ] && exit 0

# --- the file this machine sends ---------------------------------------------

if [ ! -e "$FILE" ]; then
  echo "creating $FILE: 10 MiB of random bytes"
  head -c 10485760 /dev/urandom > "$FILE"
fi
[ -f "$FILE" ] || die "$FILE is not a regular file"
[ -s "$FILE" ] || die "$FILE is empty: every trial would measure an empty drop. Remove it and rerun to recreate it."

mkdir -p "$RUN_DIR"
for f in "$OUT_A.json" "$OUT_B.json"; do
  [ ! -e "$f" ] || die "$f already exists: a run with this start time and config has been made here. Pick another --start."
done

# --- the two runs ------------------------------------------------------------

run () {
  local role="$1" seed="$2" start="$3" out="$4"
  local args=(--role "$role" --seed "$seed" --trials "$TRIALS" --slot "$SLOT" --start-epoch "$start" --out "$out.json")
  if [ "$role" = sender ]; then args+=(--file "$FILE"); else args+=(--mode "$MODE"); fi
  [ "$LOOKUP_ISP" = 1 ] && args+=(--lookup-isp)
  echo "--- run $(basename "$out"): $role, seed $seed"
  # The run's exit status is not what this script reports: a failing trial
  # is a result, not an error. Each run's own summary says how it went.
  # NOTES and EXTRA expanded this way so an empty array is safe under
  # `set -u` on bash 3.2.
  node "$DRIVER" "${args[@]}" ${NOTES[@]+"${NOTES[@]}"} ${EXTRA[@]+"${EXTRA[@]}"} 2>&1 | tee "$out.log" || true
}

run "$ROLE_A" "$STAMP-$CONFIG-a" "$START" "$OUT_A"
run "$ROLE_B" "$STAMP-$CONFIG-b" "$START_B" "$OUT_B"

cat <<EOF

=================================================================
  Both runs are done on machine $MACHINE.
  Results:  $RUN_DIR/

  Once machine $OTHER is done too, copy its two .json and .log files
  into that directory, then write the environment file:

    node $GENERATOR "$RUN_DIR" --write
    grep -n 'FILL IN' "$RUN_DIR/ENVIRONMENT.md"
=================================================================
EOF
