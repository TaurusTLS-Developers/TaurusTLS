#!/usr/bin/env bash
# Run with Bash 3.2+; each configuration uses its own process, deadline and report.
# Linux Legacy/default:
#   bash ./TaurusTLS.UT.Providers.Run.sh --executable ./TaurusTLS.UT.Providers --openssl-path ./test-assets/openssl/lib
# Linux FIPS (matching installed module/configuration required):
#   bash ./TaurusTLS.UT.Providers.Run.sh --executable ./TaurusTLS.UT.Providers --openssl-path ./test-assets/openssl/lib --fips-config ./test-assets/openssl/lib/fipsmodule.cnf
# macOS archive build (FIPS is unsupported and excluded automatically):
#   bash ./TaurusTLS.UT.Providers.Run.sh --executable ./TaurusTLS.UT.Providers
# CI example forwarding additional test arguments after --:
#   bash ./TaurusTLS.UT.Providers.Run.sh --executable "$PROVIDER_TEST_EXE" --openssl-path "$OPENSSL_PATH" --report-directory ./artifacts/providers -- --hidebanner -l:Information
# Quote each argument containing spaces. Forwarding uses arrays, never eval.
# Scenario/filter, library/FIPS selection, XML filename and exit behavior belong
# to the launcher; set them through its options rather than forwarding switches.
# --help lists launcher options. Any failed scenario makes the script exit 1.
set -o pipefail

usage() {
    cat <<'USAGE'
Usage: bash TaurusTLS.UT.Providers.Run.sh --executable PATH [options]
  --openssl-path PATH     Matching OpenSSL distribution (optional for static macOS)
  --provider MODE         auto (default), all, legacy, or fips
  --fips-config PATH      Installed fipsmodule.cnf (Linux only)
  --scenario NAME         Run a specific scenario; may be repeated
  --report-directory DIR  Output directory (default: unique temporary directory)
  --timeout SECONDS       Deadline per process, 1..600 (default: 30)
  --help                  Show this help
  -- TEST_ARGUMENTS...    Forward extra test options unchanged to every scenario

Auto runs Legacy/default cases, plus FIPS when --fips-config is supplied.
macOS always runs Legacy/default cases and rejects explicit FIPS requests.
Use absolute native-library/config paths when launching a deployed executable.
USAGE
}
die() { printf '%s\n' "$*" >&2; exit 2; }

executable=''
openssl_path="${OPENSSL_PATH:-}"
provider=auto
fips_config=''
report_directory=''
timeout_seconds=30
requested=()
test_arguments=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --) shift; test_arguments=("$@"); break ;;
        --executable|--openssl-path|--provider|--fips-config|--scenario|--report-directory|--timeout)
            [ "$#" -ge 2 ] || die "Missing value for $1"
            case "$1" in
                --executable) executable=$2 ;;
                --openssl-path) openssl_path=$2 ;;
                --provider) provider=$2 ;;
                --fips-config) fips_config=$2 ;;
                --scenario) requested+=("$2") ;;
                --report-directory) report_directory=$2 ;;
                --timeout) timeout_seconds=$2 ;;
            esac
            shift 2 ;;
        *) die "Unknown argument: $1" ;;
    esac
done
for test_argument in "${test_arguments[@]}"; do
    test_option=$(printf '%s' "${test_argument%%[:=]*}" | tr '[:upper:]' '[:lower:]')
    if [[ "$test_option" =~ ^(--?|/)(scenario|sc|run|r|runlist|rl|include|i|exclude|e|xml|xmlfile|exitbehavior|exit|osp|opensslpath|fmc|fips-module-config|help|h|\?)$ ]]; then
        die "Launcher-owned option cannot be forwarded: $test_argument; use launcher options instead"
    fi
done
[ -n "$executable" ] || die '--executable is required'
[ -f "$executable" ] && [ -x "$executable" ] || die "Not an executable file: $executable"
executable_dir=$(cd -- "$(dirname -- "$executable")" && pwd -P) || exit 2
executable="$executable_dir/$(basename -- "$executable")"
case "$provider" in auto|all|legacy|fips) ;; *) die 'Invalid --provider value' ;; esac
case "$timeout_seconds" in ''|*[!0-9]*) die '--timeout must be an integer from 1 to 600' ;; esac
[ "$timeout_seconds" -ge 1 ] && [ "$timeout_seconds" -le 600 ] || die '--timeout must be from 1 to 600'

if [ "$(uname -s)" = Darwin ]; then
    [ "$provider" != fips ] || die 'FIPS provider scenarios are unsupported on macOS'
    for scenario in "${requested[@]}"; do
        case "$scenario" in fips-*) die 'FIPS provider scenarios are unsupported on macOS' ;; esac
    done
    provider=legacy
    fips_config=''
elif [ "$provider" = auto ]; then
    if [ -n "$fips_config" ]; then provider=all; else provider=legacy; fi
fi
if [ -z "$report_directory" ]; then
    report_directory=$(mktemp -d "${TMPDIR:-/tmp}/TaurusTLS-Providers.XXXXXX") || exit 2
else
    mkdir -p -- "$report_directory" || exit 2
fi
report_directory=$(cd -- "$report_directory" && pwd -P) || exit 2
run_directory=$(mktemp -d "$report_directory/run.XXXXXX") || exit 2

active_pid=''
watchdog_pid=''
cleanup() {
    if [ -n "$watchdog_pid" ]; then
        kill "$watchdog_pid" 2>/dev/null || :
        wait "$watchdog_pid" 2>/dev/null || :
    fi
    if [ -n "$active_pid" ]; then
        kill -KILL "$active_pid" 2>/dev/null || :
        wait "$active_pid" 2>/dev/null || :
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# macOS has no built-in GNU timeout. Use only Bash, sleep and kill.
run_with_timeout() {
    local log_path=$1
    shift
    "$@" >"$log_path" 2>&1 &
    active_pid=$!
    (
        timer_pid=''
        trap 'if [ -n "$timer_pid" ]; then kill "$timer_pid" 2>/dev/null || :; fi; exit 0' TERM INT
        sleep "$timeout_seconds" &
        timer_pid=$!
        wait "$timer_pid" || exit 0
        printf 'Deadline exceeded\n' >"$log_path.timeout"
        kill -TERM "$active_pid" 2>/dev/null || exit 0
        sleep 2 &
        timer_pid=$!
        wait "$timer_pid" || exit 0
        kill -KILL "$active_pid" 2>/dev/null || :
    ) &
    watchdog_pid=$!
    local child_status=0
    wait "$active_pid" || child_status=$?
    active_pid=''
    kill "$watchdog_pid" 2>/dev/null || :
    wait "$watchdog_pid" 2>/dev/null || :
    watchdog_pid=''
    if [ -f "$log_path.timeout" ]; then return 124; fi
    return "$child_status"
}

list_log="$run_directory/scenarios.log"
run_with_timeout "$list_log" "$executable" -scenario:list --exitbehavior:Continue ||
    die "Cannot list provider scenarios; see $list_log"
available=()
while IFS= read -r scenario || [ -n "$scenario" ]; do
    scenario="${scenario%$'\r'}"
    if [[ "$scenario" =~ ^[a-z0-9]+(-[a-z0-9]+)+$ ]]; then
        available+=("$scenario")
    fi
done <"$list_log"
[ "${#available[@]}" -gt 0 ] || die "No provider scenarios listed; see $list_log"

selected=()
if [ "${#requested[@]}" -gt 0 ]; then
    for scenario in "${requested[@]}"; do
        found=false
        for known in "${available[@]}"; do
            if [ "$known" = "$scenario" ]; then found=true; break; fi
        done
        [ "$found" = true ] || die "Unknown or unsupported scenario: $scenario"
        selected+=("$scenario")
    done
else
    for scenario in "${available[@]}"; do
        case "$provider:$scenario" in
            all:*|legacy:legacy-*|legacy:default-*|fips:fips-*) selected+=("$scenario") ;;
        esac
    done
fi
[ "${#selected[@]}" -gt 0 ] || die 'No supported scenarios selected'
for scenario in "${selected[@]}"; do
    case "$scenario" in
        fips-missing-module) ;;
        fips-*) [ -n "$fips_config" ] && [ -r "$fips_config" ] ||
            die 'Selected FIPS scenarios require --fips-config with readable installed fipsmodule.cnf' ;;
    esac
done

failed=0
case_number=0
for scenario in "${selected[@]}"; do
    case_number=$((case_number + 1))
    report_stem="$run_directory/$case_number-$scenario"
    xml_path="$report_stem.xml"
    log_path="$report_stem.log"
    arguments=("-scenario:$scenario" "-osp:$openssl_path"
        --exitbehavior:Continue -cm:Quiet "--xml:$xml_path")
    if [ -n "$fips_config" ]; then arguments+=("-fmc:$fips_config"); fi
    arguments+=("${test_arguments[@]}")
    status=0
    run_with_timeout "$log_path" "$executable" "${arguments[@]}" || status=$?
    passed=false
    if [ "$status" -eq 0 ] && [ -f "$xml_path" ]; then
        case_count=$(grep -c '<test-case[[:space:]]' "$xml_path") || :
        case_line=$(grep '<test-case[[:space:]]' "$xml_path") || :
        if [ "$case_count" = 1 ] &&
            [[ "$case_line" == *'executed="True"'* && "$case_line" == *'result="Success"'* ]]; then
            passed=true
        fi
    fi
    if [ "$passed" = true ]; then
        printf 'PASS %s\n' "$scenario"
    else
        failed=$((failed + 1))
        printf 'FAIL %s (exit %s); log: %s\n' "$scenario" "$status" "$log_path"
    fi
done
printf '%s/%s scenarios passed. Reports: %s\n' \
    "$((${#selected[@]} - failed))" "${#selected[@]}" "$run_directory"
[ "$failed" -eq 0 ]
