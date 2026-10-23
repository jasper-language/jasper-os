"""Author: chatgpt. Audit soak evidence; a live snapshot never passes eight hours.
Live mode reads only the small log prefix plus atomic status. --full streams the
complete log once and is required before declaring the run accepted.
"""
import argparse
import json
import math
import pathlib
import re

READY = re.compile(r'\[JSR-SOAK\] ready cpus=8 free_frames=(\d+) objects=(\d+) pending=(\d+) heap=\((\d+), (\d+), (\d+), (\d+)\)')
PROGRESS = re.compile(r'\[JSR-SOAK\] progress rounds=(\d+) user_iterations=(\d+) free_frames=(\d+) objects=(\d+) pending=(\d+) heap=\((\d+), (\d+), (\d+), (\d+)\) conserved=true')
COMPLETE = re.compile(r'\[JSR-SOAK\] complete rounds=(\d+) user_iterations=(\d+) conserved=true')


def numeric(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError('invalid duration')
    return value


def audit(directory, full=False):
    directory = pathlib.Path(directory)
    state = json.loads((directory/'status.json').read_text())
    requested = numeric(state['requested_seconds'])
    elapsed = numeric(state.get('elapsed_seconds', 0))
    before = None
    with (directory/'serial.log').open(errors='replace') as source:
        read_bytes = 0
        for line in source:
            read_bytes += len(line)
            ready = READY.search(line)
            if ready:
                before = tuple(map(int, ready.groups()))
                break
            if read_bytes > 16*1024*1024:
                raise ValueError('ready marker absent from bounded boot prefix')
    if before is None:
        raise ValueError('no eight-CPU ready marker')
    match = PROGRESS.fullmatch(state.get('latest_progress', '').strip())
    if match is None:
        raise ValueError('no complete progress record')
    rounds, iterations, *after = map(int, match.groups())
    if rounds < 1 or iterations != rounds*1500 or tuple(after) != before:
        raise ValueError('progress count or resource drift')
    result = dict(phase=state['phase'], accepted=False, full_audit=False,
                  requested_seconds=requested, elapsed_seconds=elapsed,
                  rounds=rounds, user_iterations=iterations, resources=before,
                  ready_utc=state.get('ready_utc'), deadline_utc=state.get('deadline_utc'),
                  scope='One 8-vCPU single-thread TCG guest; correctness, not bare-metal performance')
    if state['phase'] == 'failed':
        raise ValueError('controller recorded failure: '+state.get('error', 'unknown'))
    if state['phase'] != 'complete':
        return result
    if state.get('pass_') is not True or state.get('exit_code') not in (33, 37):
        raise ValueError('controller did not complete successfully')
    if requested < 28800 or elapsed < requested:
        raise ValueError('less than eight host-monotonic hours')
    if not full:
        result['phase'] = 'awaiting_full_log_audit'
        return result
    count = ready_count = complete_count = exit_count = 0
    with (directory/'serial.log').open(errors='replace') as source:
        for line in source:
            if any(x in line for x in ('[JSR-EXIT] failure', '[JSR-SOAK] failure', '[JSR-PANIC]')):
                raise ValueError('functional failure in raw log')
            if READY.search(line):
                ready_count += 1
            current = PROGRESS.search(line)
            if current:
                if ready_count != 1 or complete_count or exit_count:
                    raise ValueError('progress outside running phase')
                n, calls, *resources = map(int, current.groups())
                count += 1
                if n != count or calls != n*1500 or tuple(resources) != before:
                    raise ValueError('missing/reordered progress or resource drift')
            complete = COMPLETE.search(line)
            if complete:
                if ready_count != 1 or complete_count or exit_count:
                    raise ValueError('completion outside running phase')
                complete_count += 1
                if tuple(map(int, complete.groups())) != (count, count*1500):
                    raise ValueError('completion count mismatch')
            if '[JSR-EXIT] success' in line or '[JSR-EXIT] timing-only' in line:
                if complete_count != 1:
                    raise ValueError('exit before completed workload')
                exit_count += 1
    if (count, ready_count, complete_count, exit_count) != (rounds, 1, 1, 1):
        raise ValueError('incomplete/restarted raw log')
    result.update(accepted=True, full_audit=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory')
    parser.add_argument('--full', action='store_true')
    args = parser.parse_args()
    print(json.dumps(audit(args.directory, args.full), indent=2))
