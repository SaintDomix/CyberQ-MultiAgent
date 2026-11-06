"""Durable live journal and append-only projections; no training or raw requests."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile


class IntegrityFault(ValueError):
    """Fixed audit reason; never attach arbitrary raw-line/exception text."""


def encode(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


def digest(value):return hashlib.sha256(encode(value).encode()).hexdigest()


def sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def atomic_json(path,value):
    path=Path(path)
    fd,name=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as handle:
            handle.write(encode(value)+'\n');handle.flush();os.fsync(handle.fileno())
        os.replace(name,path);sync_directory(path.parent)
    finally:
        if os.path.exists(name):os.unlink(name)  # Own uncommitted temporary file only.


def append_json(path,value):
    with Path(path).open('ab') as handle:
        handle.write((encode(value)+'\n').encode());handle.flush();os.fsync(handle.fileno())


class Journal:
    """SQLite FULL synchronous commit is authoritative for both projections.

    Restore missing complete JSONL suffixes after a crash. Never remove/rewrite
    torn or corrupt history: require operator inspection and fail closed.
    """
    def __init__(self,root):
        self.root=Path(root)
        self.db=sqlite3.connect(self.root/'journal.sqlite3')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS results (sequence INTEGER PRIMARY KEY, record_id TEXT UNIQUE NOT NULL, payload TEXT NOT NULL, sha256 TEXT NOT NULL)')
        self.db.commit()
        self.sequence=self.db.execute('SELECT COALESCE(MAX(sequence),0) FROM results').fetchone()[0]
        self.recover()

    def entries(self):
        expected_sequence=0
        for sequence,record_id,payload,sha in self.db.execute('SELECT sequence,record_id,payload,sha256 FROM results ORDER BY sequence'):
            expected_sequence+=1
            if sequence!=expected_sequence:raise IntegrityFault('JOURNAL_SEQUENCE_GAP')
            if hashlib.sha256(payload.encode()).hexdigest()!=sha:raise IntegrityFault('JOURNAL_HASH_MISMATCH')
            value=json.loads(payload)
            if value['prediction']['sequence']!=sequence or value['prediction']['record_id']!=record_id:raise IntegrityFault('JOURNAL_ID_MISMATCH')
            yield value

    def recover(self):
        for name,key in [('windows.jsonl','window'),('predictions.jsonl','prediction')]:
            path=self.root/name;path.touch(exist_ok=True)
            with path.open('rb') as handle:
                for value in self.entries():
                    line=handle.readline()
                    if not line:
                        append_json(path,value[key]);handle.seek(0,2);continue
                    if not line.endswith(b'\n'):raise IntegrityFault('TORN_OUTPUT_RECORD')
                    try:actual=json.loads(line)
                    except (ValueError,UnicodeError):raise IntegrityFault('CORRUPT_OUTPUT_RECORD') from None
                    if actual!=value[key]:raise IntegrityFault('OUTPUT_JOURNAL_MISMATCH')
                if handle.read(1):raise IntegrityFault('UNJOURNALED_OUTPUT')
        if self.sequence:
            value=json.loads(self.db.execute('SELECT payload FROM results ORDER BY sequence DESC LIMIT 1').fetchone()[0])
            atomic_json(self.root/'latest.json',value['prediction'])

    def existing(self,record_id,window):
        found=self.db.execute('SELECT payload,sha256 FROM results WHERE record_id=?',(record_id,)).fetchone()
        if found is None:return False
        payload,sha=found
        if hashlib.sha256(payload.encode()).hexdigest()!=sha:raise IntegrityFault('JOURNAL_HASH_MISMATCH')
        if json.loads(payload)['window']!=window:raise IntegrityFault('REPLAY_WINDOW_CHANGED')
        return True

    def observed(self,record_id,start,end,sha):
        found=self.db.execute('SELECT payload,sha256 FROM results WHERE record_id=?',(record_id,)).fetchone()
        if found is None:return False
        payload,expected=found
        if hashlib.sha256(payload.encode()).hexdigest()!=expected:raise IntegrityFault('JOURNAL_HASH_MISMATCH')
        return {'start':start,'end':end,'sha256':sha} in json.loads(payload)['window']['source_byte_ranges']

    def summaries(self):
        # Exact quantiles without retaining all historical windows in Python RAM.
        self.db.create_function('ms',2,lambda payload,key:json.loads(payload)['prediction'][key])
        summaries={}
        for key in ('processing_duration_ms','window_close_to_emission_ms'):
            count,low,high,mean=self.db.execute('SELECT COUNT(*),MIN(ms(payload,?)),MAX(ms(payload,?)),AVG(ms(payload,?)) FROM results',(key,key,key)).fetchone()
            def percentile(q):
                rank=(count-1)*q;lower=int(rank);upper=min(lower+1,count-1)
                values=[self.db.execute('SELECT ms(payload,?) FROM results ORDER BY ms(payload,?) LIMIT 1 OFFSET ?',(key,key,index)).fetchone()[0] for index in (lower,upper)]
                return values[0]+(values[1]-values[0])*(rank-lower)
            summaries[key]={'count':count,'min':low,'max':high,'mean':mean,'median':percentile(.5),'p95':percentile(.95)} if count else {'count':0}
        self.db.create_function('explanation_failed',1,lambda payload:int(json.loads(payload)['prediction']['shap_explanation']['status'] not in {'AVAILABLE','NOT_REQUESTED'}))
        failures=self.db.execute('SELECT COALESCE(SUM(explanation_failed(payload)),0) FROM results').fetchone()[0]
        return summaries,failures

    def persist(self,window,prediction):
        prediction['sequence']=self.sequence+1
        payload=encode({'window':window,'prediction':prediction})
        with self.db:
            self.db.execute('INSERT INTO results VALUES (?,?,?,?)',(self.sequence+1,prediction['record_id'],payload,hashlib.sha256(payload.encode()).hexdigest()))
        self.sequence+=1
        # Output durability precedes caller checkpoint. Recover fills a missing
        # projection suffix if the process dies between these writes.
        append_json(self.root/'windows.jsonl',window)
        append_json(self.root/'predictions.jsonl',prediction)
        atomic_json(self.root/'latest.json',prediction)

    def close(self):self.db.close()
