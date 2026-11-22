"""AI-File-Integrity local dashboard: intentionally no monitoring/AI rule changes."""
from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
import subprocess
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request

PROJECT_ROOT = Path(os.environ.get('AFI_PROJECT_ROOT', Path(__file__).resolve().parents[1])).resolve()
DB_PATH = PROJECT_ROOT / 'logs' / 'security_events.db'
CONTROL_COMMAND = os.environ.get('AFI_CONTROL_COMMAND', '/usr/local/sbin/afi-admin')
CONTROL_TIMEOUT = 16
AI_TIMEOUT = 240
APP_TOKEN = secrets.token_urlsafe(36)

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config.update(JSON_SORT_KEYS=False, MAX_CONTENT_LENGTH=20_000)
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()
_ai_lock = threading.Lock()

CASES = [
    ('Attack', 'Unauthorized access', 2262, 'simulated_attack'),
    ('Attack', 'Unauthorized modification', 2323, 'simulated_attack'),
    ('Attack', 'Rapid deletion', 2347, 'simulated_attack'),
    ('Attack', 'Permission change', 2355, 'simulated_attack'),
    ('Attack', 'Compromised account', 2357, 'simulated_attack'),
    ('Attack', 'Rapid modification', 2372, 'simulated_attack'),
    ('Attack', 'Process interaction', 2379, 'simulated_attack'),
    ('Benign control', 'Routine file edits', 2400, 'benign'),
    ('Benign control', 'Legitimate cleanup', 2404, 'benign'),
    ('Benign control', 'Restrictive chmod', 2408, 'benign'),
    ('Benign control', 'Batch modifications', 2492, 'benign'),
    ('Deletion comparison', 'Single-file deletion', 2428, 'benign'),
    ('Deletion comparison', 'Delayed test-labeled deletion', 2434, 'benign'),
    ('Deletion comparison', 'Delayed business-labeled deletion', 2445, 'benign'),
    ('Deletion comparison', 'Manual terminal deletion', 2487, 'benign'),
]


def connection():
    if not DB_PATH.is_file():
        raise FileNotFoundError(f'No SQLite database at {DB_PATH}')
    db = sqlite3.connect(DB_PATH.as_uri() + '?mode=ro', uri=True, timeout=4)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA query_only=ON')
    db.execute('PRAGMA busy_timeout=3000')
    return db


def fetch_all(sql, params=()):
    with connection() as db:
        return [dict(row) for row in db.execute(sql, params).fetchall()]


def fetch_one(sql, params=()):
    with connection() as db:
        row = db.execute(sql, params).fetchone()
        return dict(row) if row else None


def safe_json(value):
    if not value:
        return {}
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return {'raw': str(value)}


def numeric(value, default, minimum, maximum):
    try:
        n = int(value)
        return max(minimum, min(n, maximum))
    except (ValueError, TypeError):
        return default


def command(*args, timeout=CONTROL_TIMEOUT):
    result = subprocess.run(
        ['sudo', '-n', CONTROL_COMMAND, *args], capture_output=True,
        text=True, timeout=timeout, cwd=str(PROJECT_ROOT),
    )
    return {'ok': result.returncode == 0,
            'message': (result.stdout or result.stderr).strip()[-25000:],
            'returncode': result.returncode}


def service_states():
    statuses = {}
    for name, unit in [('monitor', 'ai-file-integrity-monitor.service'),
                       ('detector', 'ai-file-integrity-detector.service'),
                       ('auditd', 'auditd.service')]:
        try:
            res = subprocess.run(['/usr/bin/systemctl', 'is-active', unit],
                                 capture_output=True, text=True, timeout=3)
            statuses[name] = (res.stdout.strip() or 'unknown')
        except (OSError, subprocess.TimeoutExpired):
            statuses[name] = 'unavailable'
    return statuses


@app.before_request
def local_protection():
    # This app is deliberately local-only; never expose it through a reverse proxy.
    hostname = request.host.split(':')[0].strip('[]').lower()
    if hostname not in {'localhost', '127.0.0.1', '::1'}:
        abort(403)
    if request.method not in ('GET', 'HEAD', 'OPTIONS'):
        if not secrets.compare_digest(request.headers.get('X-AFI-CSRF', ''), APP_TOKEN):
            abort(403)
        if request.mimetype != 'application/json':
            abort(415)


@app.errorhandler(Exception)
def handle_error(error):
    from werkzeug.exceptions import HTTPException
    if isinstance(error, HTTPException):
        return jsonify(error=error.description), error.code
    if isinstance(error, (sqlite3.Error, FileNotFoundError, PermissionError)):
        return jsonify(error=str(error)), 503
    app.logger.exception('API error')
    return jsonify(error='Unexpected server error; consult dashboard terminal'), 500


@app.get('/')
def index():
    return render_template('index.html', csrf=APP_TOKEN)


@app.get('/api/summary')
def summary():
    totals = fetch_one('''
      SELECT (SELECT count(*) FROM events) AS events,
             (SELECT count(*) FROM findings) AS findings,
             (SELECT count(*) FROM ai_assessments) AS assessments,
             (SELECT count(*) FROM findings WHERE status='OPEN') AS open_findings
    ''')
    severity = fetch_all('SELECT severity, COUNT(*) AS count FROM findings GROUP BY severity')
    assessments = fetch_all('SELECT classification, count(*) AS count FROM ai_assessments GROUP BY classification')
    timeline = fetch_all('''
      SELECT SUBSTR(first_seen,1,10) AS day, COUNT(*) AS count
      FROM findings WHERE first_seen >= datetime('now','-14 days')
      GROUP BY SUBSTR(first_seen,1,10) ORDER BY day ASC
    ''')
    return jsonify(totals=totals, severity=severity, assessments=assessments,
                   timeline=timeline, services=service_states(), time=datetime.now(timezone.utc).isoformat())


@app.get('/api/findings')
def findings():
    limit = numeric(request.args.get('limit'), 40, 1, 100)
    page = numeric(request.args.get('page'), 1, 1, 100000)
    where, params = [], []
    query = request.args.get('q', '').strip()[:180]
    if query:
        where.append('(f.file_path LIKE ? OR f.username LIKE ? OR f.event_types LIKE ? OR CAST(f.id AS TEXT) = ?)')
        params += [f'%{query}%', f'%{query}%', f'%{query}%', query]
    severity = request.args.get('severity', '').upper()
    if severity in {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
        where.append('f.severity = ?'); params.append(severity)
    status = request.args.get('status', '').upper()
    if status in {'OPEN', 'INVESTIGATING', 'RESOLVED'}:
        where.append('f.status = ?'); params.append(status)
    classified = request.args.get('classification', '').upper()
    if classified in {'BENIGN', 'SUSPICIOUS', 'INCONCLUSIVE'}:
        where.append('EXISTS (SELECT 1 FROM ai_assessments a WHERE a.finding_id = f.id AND a.classification = ?)')
        params.append(classified)
    clause = (' WHERE ' + ' AND '.join(where)) if where else ''
    total = fetch_one('SELECT COUNT(*) AS count FROM findings f' + clause, tuple(params))['count']
    rows = fetch_all('''
      SELECT f.id, f.first_seen, f.last_seen, f.event_types, f.file_path,
             f.username, f.audit_event_id, f.risk_score, f.severity, f.status,
             (SELECT count(*) FROM ai_assessments a WHERE a.finding_id=f.id) AS ai_count,
             (SELECT classification FROM ai_assessments a WHERE a.finding_id=f.id ORDER BY id DESC LIMIT 1) AS latest_classification
      FROM findings f''' + clause + ' ORDER BY f.id DESC LIMIT ? OFFSET ?',
      tuple(params) + (limit, (page-1)*limit))
    return jsonify(rows=rows, count=total, page=page, limit=limit)


@app.get('/api/findings/<int:fid>')
def finding_detail(fid):
    found = fetch_one('SELECT * FROM findings WHERE id=?', (fid,))
    if not found: abort(404)
    found['reasons'] = found.get('reasons') or ''
    assessments = fetch_all('''
      SELECT a.id, a.created_at, a.model, a.classification, a.severity,
             a.confidence, a.tool_calls,
             v.status AS validation_status, v.verified_claims, v.total_claims
      FROM ai_assessments a LEFT JOIN ai_assessment_validations v ON v.assessment_id=a.id
      WHERE a.finding_id=? ORDER BY a.id DESC LIMIT 100
    ''', (fid,))
    history = fetch_all('''SELECT id, timestamp, event_type, details FROM events
      WHERE file_path=? ORDER BY id DESC LIMIT 30''', (found['file_path'],))
    return jsonify(finding=found, assessments=assessments, history=history)


@app.get('/api/assessments/<int:aid>')
def assessment_detail(aid):
    item = fetch_one('''
      SELECT a.*, v.status AS validation_status, v.verified_claims,
             v.total_claims, v.validation_json
      FROM ai_assessments a LEFT JOIN ai_assessment_validations v ON v.assessment_id=a.id
      WHERE a.id=?''', (aid,))
    if not item: abort(404)
    item['assessment'] = safe_json(item.pop('assessment_json'))
    item['validation'] = safe_json(item.pop('validation_json'))
    return jsonify(item)


@app.get('/api/assessments')
def assessments_list():
    limit = numeric(request.args.get('limit'), 60, 1, 150)
    return jsonify(rows=fetch_all('''
      SELECT a.id,a.finding_id,a.created_at,a.model,a.classification,
             a.severity,a.confidence,a.tool_calls,
             v.status AS validation_status,v.verified_claims,v.total_claims,
             f.file_path,f.event_types
      FROM ai_assessments a JOIN findings f ON f.id=a.finding_id
      LEFT JOIN ai_assessment_validations v ON v.assessment_id=a.id
      ORDER BY a.id DESC LIMIT ?''', (limit,)))


@app.get('/api/events')
def events():
    limit = numeric(request.args.get('limit'), 40, 1, 100)
    return jsonify(rows=fetch_all('''
      SELECT id,timestamp,event_type,file_path,details FROM events ORDER BY id DESC LIMIT ?
    ''', (limit,)))


@app.get('/api/evaluation')
def evaluation():
    ids = tuple(entry[2] for entry in CASES)
    placeholders = ','.join('?' * len(ids))
    rows = fetch_all(f'''
      SELECT a.id,a.finding_id,a.classification,a.severity,a.confidence,
             a.tool_calls,v.status AS validation_status,
             v.verified_claims,v.total_claims,v.validation_json
      FROM ai_assessments a LEFT JOIN ai_assessment_validations v ON v.assessment_id=a.id
      WHERE a.finding_id IN ({placeholders}) AND a.id>=23 ORDER BY a.id ASC
    ''', ids)
    by_finding = {}
    for entry in rows:
        by_finding.setdefault(entry['finding_id'], []).append(entry)
    cases = []
    for group, label, fid, ground_truth in CASES:
        sample = by_finding.get(fid, [])
        counts = Counter(row['classification'] for row in sample)
        claims = sum(row['total_claims'] or 0 for row in sample)
        verified = sum(row['verified_claims'] or 0 for row in sample)
        relevant = []
        for row in sample:
            coverage = safe_json(row.get('validation_json')).get('incident_coverage', {})
            if coverage.get('status') not in (None, 'NOT_APPLICABLE', 'UNAVAILABLE'):
                relevant.append(coverage)
        cases.append({
            'category': group, 'name': label, 'finding_id': fid, 'ground_truth': ground_truth,
            'runs': len(sample), 'counts': dict(counts),
            'agreement': round(max(counts.values()) / len(sample) * 100, 1) if sample else None,
            'verified_claims': verified, 'total_claims': claims,
            'verified_assessments': sum(r['validation_status']=='VERIFIED_FIELDS' for r in sample),
            'complete_incidents': sum(r['status']=='COMPLETE' for r in relevant),
            'incident_applicable': len(relevant),
        })
    return jsonify(cases=cases,
                   note='Fixed 15-case historical cohort, not a general accuracy estimate. Subsequent investigations of these findings also appear in this view.')


@app.get('/api/services')
def services():
    return jsonify(services=service_states())


@app.post('/api/services/<service>/<action>')
def service_action(service, action):
    if service not in {'monitor', 'detector'} or action not in {'start', 'stop', 'restart'}:
        abort(404)
    try:
        result = command('service', service, action)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return jsonify(error=f'Control unavailable: {type(exc).__name__}'), 503
    return jsonify(**result, services=service_states()), (200 if result['ok'] else 409)


@app.get('/api/findings/<int:fid>/audit')
def finding_audit(fid):
    found = fetch_one('SELECT audit_event_id,first_seen FROM findings WHERE id=?', (fid,))
    if not found: abort(404)
    if not found['audit_event_id']:
        return jsonify(events=[], message='This finding has no correlated audit event ID.')
    # The ID + timestamp avoids incorrect matches if audit sequence numbers repeat.
    try:
        result = command('audit', str(found['audit_event_id']), found['first_seen'][:19], timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return jsonify(error='Audit lookup unavailable'), 503
    if not result['ok']:
        return jsonify(error=result['message'] or 'Audit lookup failed'), 503
    try:
        records = json.loads(result['message'])
    except json.JSONDecodeError:
        return jsonify(error='Invalid audit lookup response'), 502
    return jsonify(events=records.get('matches', []), total=records.get('total_matches', 0))


@app.post('/api/findings/<int:fid>/status')
def set_status(fid):
    payload = request.get_json(silent=True) or {}
    status = str(payload.get('status', '')).upper()
    if status not in {'OPEN', 'INVESTIGATING', 'RESOLVED'}:
        return jsonify(error='Invalid status'), 400
    if not fetch_one('SELECT id FROM findings WHERE id=?', (fid,)):
        abort(404)
    try:
        result = command('status', str(fid), status)
    except (OSError, subprocess.TimeoutExpired):
        return jsonify(error='Status helper unavailable'), 503
    return jsonify(**result), (200 if result['ok'] else 409)


def _run_investigation(job_id, fid):
    with _ai_lock:
        with _jobs_lock:
            _jobs[job_id]['status'] = 'running'
            _jobs[job_id]['started_at'] = datetime.now(timezone.utc).isoformat()
        try:
            result = command('investigate', str(fid), timeout=AI_TIMEOUT)
            with _jobs_lock:
                _jobs[job_id].update(status='complete' if result['ok'] else 'failed',
                                     result=result['message'], returncode=result['returncode'])
        except subprocess.TimeoutExpired:
            with _jobs_lock:
                _jobs[job_id].update(status='failed', result='Investigation exceeded 240 seconds')
        except OSError as exc:
            with _jobs_lock:
                _jobs[job_id].update(status='failed', result=f'Investigation helper unavailable: {type(exc).__name__}')
        finally:
            with _jobs_lock:
                _jobs[job_id]['ended_at'] = datetime.now(timezone.utc).isoformat()


@app.post('/api/findings/<int:fid>/investigate')
def start_investigation(fid):
    if not fetch_one('SELECT id FROM findings WHERE id=?', (fid,)):
        abort(404)
    with _jobs_lock:
        active_jobs = [j for j in _jobs.values() if j['status'] in {'queued', 'running'}]
        if active_jobs:
            return jsonify(error='An AI investigation is already running. Wait for it to complete.'), 409
        job_id = secrets.token_urlsafe(12)
        _jobs[job_id] = {'id':job_id, 'finding_id': fid, 'status':'queued',
                         'created_at':datetime.now(timezone.utc).isoformat(), 'result':''}
        # Bound memory while retaining current jobs.
        if len(_jobs) > 100:
            for key in list(_jobs)[:-80]:
                if _jobs[key]['status'] not in {'queued', 'running'}:
                    _jobs.pop(key, None)
    threading.Thread(target=_run_investigation, args=(job_id, fid), daemon=True).start()
    return jsonify(job=_jobs[job_id]), 202


@app.get('/api/jobs/<job_id>')
def job_status(job_id):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job: abort(404)
        return jsonify(job=dict(job))


@app.get('/api/logs/<service>')
def logs(service):
    if service not in {'monitor', 'detector', 'auditd'}:
        abort(404)
    try:
        result = command('logs', service)
    except (OSError, subprocess.TimeoutExpired):
        return jsonify(error='Log helper unavailable'), 503
    return jsonify(**result), (200 if result['ok'] else 409)


if __name__ == '__main__':
    # Single process required for in-memory paid API job tracking.
    app.run(host='127.0.0.1', port=int(os.environ.get('AFI_DASHBOARD_PORT', '8765')),
            debug=False, threaded=True, use_reloader=False)
