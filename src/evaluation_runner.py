#!/usr/bin/env python3
"""Standalone, non-invasive AI File Integrity evaluation orchestrator."""
import argparse
import csv
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / 'logs' / 'security_events.db'
MANIFEST = ROOT / 'logs' / 'evaluation_manifest.json'
EXPORT_DIR = ROOT / 'evaluation_results'
SCENARIOS = (
    'unauthorized_access', 'unauthorized_modification', 'deletion',
    'permission_change', 'compromised_account', 'rapid_modification',
    'process_interaction',
)
# The designated primary finding is not necessarily the only finding generated.
TARGET = {
    'unauthorized_access': ('ACCESS_DENIED', '/opt/organization/marketing'),
    'unauthorized_modification': ('UNAUTHORIZED_MODIFICATION', None),
    'deletion': ('DELETED', None),
    'permission_change': ('PERMISSION_CHANGED', None),
    'compromised_account': ('ACCESS_DENIED', '/opt/organization/marketing'),
    'rapid_modification': ('MODIFIED', None),
    'process_interaction': ('CREATED', None),
}
RUN_DIR_RE = re.compile(r'/opt/organization/[^\s\'"<>]*/run_[a-zA-Z0-9_-]+')


def connect():
    connection = sqlite3.connect(f'file:{DB}?mode=ro', uri=True, timeout=15)
    connection.row_factory = sqlite3.Row
    return connection


def query(sql, params=()):
    with connect() as conn:
        return [dict(row) for row in conn.execute(sql, params)]


def max_id(table):
    return query(f'SELECT COALESCE(MAX(id), 0) AS n FROM {table}')[0]['n']


def load_manifest():
    if not MANIFEST.exists():
        return {'version': 1, 'scenarios': {}}
    return json.loads(MANIFEST.read_text())


def save_manifest(data):
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    temp = MANIFEST.with_suffix('.tmp')
    temp.write_text(json.dumps(data, indent=2) + '\n')
    os.replace(temp, MANIFEST)


def assessments(finding_id, after_id):
    return query('''
        SELECT a.id, a.finding_id, a.created_at, a.model,
               a.classification, a.severity, a.confidence, a.tool_calls,
               a.assessment_json, v.status AS validation_status,
               v.verified_claims, v.total_claims, v.validation_json
        FROM ai_assessments a
        LEFT JOIN ai_assessment_validations v ON v.assessment_id = a.id
        WHERE a.finding_id = ? AND a.id > ?
        ORDER BY a.id
    ''', (finding_id, after_id))


def invoke(args, timeout):
    print('$', ' '.join(args), flush=True)
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True,
                            timeout=timeout, env=os.environ.copy())
    if result.stdout:
        print(result.stdout, end='' if result.stdout.endswith('\n') else '\n', flush=True)
    if result.stderr:
        print(result.stderr, file=sys.stderr, flush=True)
    if result.returncode:
        raise RuntimeError(f'Command exited with code {result.returncode}')
    return result.stdout


def candidate_findings(scenario, baseline, run_dir):
    event, fixed_path = TARGET[scenario]
    rows = query('''
        SELECT id, event_types, username, risk_score, severity,
               audit_event_id, file_path, reasons
        FROM findings WHERE id > ? ORDER BY id
    ''', (baseline,))
    matches = []
    for row in rows:
        types = {s.strip() for s in (row['event_types'] or '').split(',')}
        if event not in types or row['username'] != 'alice':
            continue
        path = row['file_path'] or ''
        if fixed_path is not None and path != fixed_path:
            continue
        if scenario == 'unauthorized_modification':
            # Denied write targets HR, outside the finance test directory.
            marker = Path(run_dir).name if run_dir else None
            if not marker or not path.startswith('/opt/organization/hr/d3_denied_') or marker not in path:
                continue
        elif fixed_path is None and (not run_dir or not path.startswith(run_dir + '/')):
            continue
        if scenario == 'permission_change' and '0o666' not in (row['reasons'] or ''):
            continue
        matches.append(row)
    return matches


def choose_finding(scenario, baseline, run_dir, override=None):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        found = candidate_findings(scenario, baseline, run_dir)
        if override is not None:
            selected = [item for item in found if item['id'] == override]
            if selected:
                return selected[0]
        elif found:
            # A burst may yield several equivalent file findings. Use the
            # lowest database ID deterministically; retain the other IDs.
            if scenario in ('deletion', 'rapid_modification', 'process_interaction'):
                return found[0]
            if len(found) == 1:
                return found[0]
            raise RuntimeError(
                f'Ambiguous {scenario} finding selection: {[f["id"] for f in found]}. '
                'Use --finding-id ID after reviewing the candidates.'
            )
        time.sleep(2)
    raise RuntimeError(
        f'No matching finding within 60 seconds for {scenario} '
        f'(baseline ID {baseline}, run directory {run_dir}). '
        'Ensure auditd, monitor and continuous detector are running.'
    )


def infer_run_dir(output, baseline):
    explicit = {s.rstrip('/.,:;') for s in RUN_DIR_RE.findall(output)}
    if len(explicit) == 1:
        return explicit.pop()
    if len(explicit) > 1:
        raise RuntimeError(f'Multiple run directories in simulator output: {sorted(explicit)}')
    rows = query('SELECT file_path FROM findings WHERE id > ?', (baseline,))
    paths = set()
    for row in rows:
        match = RUN_DIR_RE.search(row['file_path'] or '')
        if match:
            paths.add(match.group().rstrip('/'))
    if len(paths) == 1:
        return paths.pop()
    raise RuntimeError('Could not uniquely identify simulator run directory. '
                       f'Candidates: {sorted(paths)}; select finding manually.')


def finish_selection(name, record, manifest, finding_override=None):
    baseline = record['baseline_finding_id']
    output = record.get('simulator_output', '')
    try:
        run_dir = infer_run_dir(output, baseline)
    except RuntimeError:
        time.sleep(7)
        run_dir = infer_run_dir(output, baseline)
    selected = choose_finding(name, baseline, run_dir, finding_override)
    print(f'Selected finding {selected["id"]}: {selected["event_types"]} '
          f'{selected["file_path"]}', flush=True)
    record.update({
        'finding_id': selected['id'],
        'run_directory': run_dir,
        'phase': 'ready',
        'selection': {'event_types': selected['event_types'],
                      'file_path': selected['file_path']},
    })
    # The full simulator output need not live in the persistent manifest.
    record.pop('simulator_output', None)
    save_manifest(manifest)
    return record


def create_scenario_record(name, manifest, finding_override=None):
    baseline = max_id('findings')
    print(f'\n=== {name}: simulator (finding baseline {baseline}) ===', flush=True)
    record = {
        'phase': 'awaiting_simulation',
        'baseline_finding_id': baseline,
        'baseline_assessment_id': max_id('ai_assessments'),
        'started_at': datetime.now(timezone.utc).isoformat(),
    }
    manifest['scenarios'][name] = record
    save_manifest(manifest)
    return resume_selection(name, record, manifest, finding_override)


def resume_selection(name, record, manifest, finding_override=None):
    if record['phase'] == 'awaiting_simulation':
        # A previous run could have stopped after the simulator finished
        # but before the run directory was saved. Avoid rerunning it.
        try:
            infer_run_dir('', record['baseline_finding_id'])
        except RuntimeError:
            stdout = invoke(
                [sys.executable, 'src/attack_simulator.py', '--scenario', name],
                120,
            )
            record['simulator_output'] = stdout
        record['phase'] = 'awaiting_finding'
        save_manifest(manifest)
    return finish_selection(name, record, manifest, finding_override)


def register_existing(name, finding_id, manifest):
    rows = query('SELECT id, event_types, file_path FROM findings WHERE id = ?', (finding_id,))
    if not rows:
        raise RuntimeError(f'Finding {finding_id} does not exist')
    existing = query('SELECT MIN(id) AS first_id, COUNT(*) AS count '
                     'FROM ai_assessments WHERE finding_id = ?', (finding_id,))[0]
    if not existing['count']:
        raise RuntimeError(f'Finding {finding_id} has no saved AI assessments')
    record = {
        'finding_id': finding_id,
        'phase': 'ready',
        'baseline_finding_id': None,
        'baseline_assessment_id': existing['first_id'] - 1,
        'run_directory': None,
        'started_at': 'historical_manual_registration',
        'selection': {'event_types': rows[0]['event_types'],
                      'file_path': rows[0]['file_path']},
    }
    manifest['scenarios'][name] = record
    save_manifest(manifest)
    print(f'Registered {name}: finding {finding_id}, '
          f'{existing["count"]} existing assessments')


def run_scenario(name, manifest, runs, finding_override=None):
    record = manifest['scenarios'].get(name)
    if record is None:
        record = create_scenario_record(name, manifest, finding_override)
    elif record.get('phase') in ('awaiting_simulation', 'awaiting_finding'):
        print(f'\n=== Resuming {name}, waiting for finding ===')
        record = resume_selection(name, record, manifest, finding_override)
    else:
        print(f'\n=== Resuming {name}, finding {record["finding_id"]} ===')
    selected = record['finding_id']
    cutoff = record['baseline_assessment_id']
    existing = assessments(selected, cutoff)
    print(f'Already saved: {len(existing)} assessment(s). Target: {runs}.')
    while len(existing) < runs:
        before = max_id('ai_assessments')
        print(f'\n=== {name}: investigation {len(existing) + 1}/{runs} ===', flush=True)
        try:
            invoke([sys.executable, 'src/ai_investigator.py', '--finding', str(selected)], 240)
        except Exception:
            # An assessment may still have been committed before an error.
            existing = assessments(selected, cutoff)
            print(f'Assessment rows now present: {len(existing)}', file=sys.stderr)
            raise
        existing = assessments(selected, cutoff)
        if not any(r['id'] > before for r in existing):
            raise RuntimeError('Investigation returned success without saving a new assessment')
    print(f'Completed {name}: {len(existing)} assessment(s) saved.')


def export_results(manifest):
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    detail = []
    summaries = []
    for name, record in manifest['scenarios'].items():
        items = assessments(record['finding_id'], record['baseline_assessment_id'])
        if not items:
            continue
        distribution = Counter(r['classification'] for r in items)
        validated = [r for r in items if r['validation_status'] == 'VERIFIED_FIELDS']
        claims_good = sum(r['verified_claims'] or 0 for r in validated)
        claims_total = sum(r['total_claims'] or 0 for r in validated)
        for row in items:
            detail.append({
                'scenario': name,
                'finding_id': record['finding_id'],
                'assessment_id': row['id'],
                'created_at': row['created_at'],
                'model': row['model'],
                'classification': row['classification'],
                'severity': row['severity'],
                'confidence': row['confidence'],
                'tool_calls': row['tool_calls'],
                'validation_status': row['validation_status'] or 'NO_VALIDATION',
                'verified_claims': row['verified_claims'],
                'total_claims': row['total_claims'],
                'assessment_json': row['assessment_json'],
                'validation_json': row['validation_json'],
            })
        summaries.append({
            'scenario': name,
            'finding_id': record['finding_id'],
            'runs': len(items),
            'suspicious': distribution['SUSPICIOUS'],
            'benign': distribution['BENIGN'],
            'inconclusive': distribution['INCONCLUSIVE'],
            'modal_classification_agreement_pct': round(100 * max(distribution.values()) / len(items), 1),
            'verified_fields_assessments': len(validated),
            'needs_review_assessments': sum(r['validation_status'] == 'NEEDS_REVIEW' for r in items),
            'missing_validation_assessments': sum(r['validation_status'] is None for r in items),
            'verified_claims': claims_good,
            'checked_claims': claims_total,
            'mean_tool_calls': round(sum(r['tool_calls'] for r in items) / len(items), 2),
        })
    for filename, rows in (('ai_evaluation_details.csv', detail),
                           ('ai_evaluation_summary.csv', summaries)):
        path = EXPORT_DIR / filename
        if rows:
            with path.open('w', newline='') as file:
                writer = csv.DictWriter(file, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
            print(f'Exported {len(rows)} rows: {path}')
        else:
            print(f'No records available for {filename}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--scenario', choices=SCENARIOS)
    group.add_argument('--all', action='store_true')
    group.add_argument('--export', action='store_true')
    group.add_argument('--register-existing', nargs=2, metavar=('SCENARIO', 'FINDING_ID'))
    parser.add_argument('--runs', type=int, default=5)
    parser.add_argument('--skip', nargs='*', choices=SCENARIOS, default=[])
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--finding-id', type=int, help='Explicit selection when a fresh scenario is ambiguous')
    args = parser.parse_args()
    if args.runs < 1 or args.runs > 100:
        parser.error('--runs must be between 1 and 100')
    if not DB.exists():
        parser.error(f'Database not found: {DB}')
    manifest = load_manifest()
    if args.export:
        export_results(manifest)
        return
    if args.register_existing:
        name, string_id = args.register_existing
        if name not in SCENARIOS or not string_id.isdigit():
            parser.error('--register-existing requires valid scenario and numeric finding ID')
        if name in manifest['scenarios']:
            parser.error(f'{name} already recorded; refusing to overwrite')
        if not args.dry_run:
            register_existing(name, int(string_id), manifest)
            export_results(manifest)
        else:
            print(f'DRY RUN: register {name}, finding {string_id}')
        return
    selected = [args.scenario] if args.scenario else list(SCENARIOS)
    selected = [name for name in selected if name not in args.skip]
    if args.dry_run:
        for name in selected:
            record = manifest['scenarios'].get(name)
            saved = (len(assessments(record['finding_id'], record['baseline_assessment_id']))
                     if record and record.get('finding_id') else 0)
            print(f'{name}: {saved}/{args.runs} stored; '
                  f'{"resume finding " + str(record.get("finding_id", "pending")) if record else "new simulation"}')
        return
    if not os.environ.get('OPENAI_API_KEY'):
        parser.error('OPENAI_API_KEY not loaded; source .env before running')
    if os.geteuid() != 0:
        parser.error('Run under sudo with --preserve-env=OPENAI_API_KEY,OPENAI_MODEL')
    try:
        for name in selected:
            run_scenario(name, manifest, args.runs, args.finding_id)
            export_results(manifest)
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        print(f'\nSTOPPED: {error}', file=sys.stderr)
        print('Existing results and manifest retained. Fix the issue and rerun to resume.', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
