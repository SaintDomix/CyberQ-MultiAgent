"""Ubuntu byte-offset capture agent. Reads Apache only; immutable evidence per run."""
from datetime import datetime, timezone, timedelta
import fcntl
import json
import os
from pathlib import Path
import time
from .planning import sha,source_hashes,source_files
from .safety import validate_schedule,validate_result


def write(path,value):
    with Path(path).open('x') as f:json.dump(value,f,indent=2,sort_keys=True,allow_nan=False);f.write('\n')


def iso(now): return now.astimezone(timezone.utc).isoformat()


class CaptureServer:
    def __init__(self,root,log,clock=lambda:datetime.now(timezone.utc),sleep=time.sleep):
        self.root=Path(root);self.log=Path(log);self.clock=clock;self.sleep=sleep

    def initialize(self,plan):
        validate_schedule(plan)
        if plan['generator_files_sha256']!=source_hashes():raise ValueError('Kali/Ubuntu generator source mismatch; synchronize from Ubuntu')
        if self.root.exists():raise ValueError('Capture root must be new; no overwrite')
        # Reject non-combined/extended secret-bearing formats before generating traffic.
        from ..adapters.apache import parse_line
        with self.log.open('rb') as log:
            log.seek(0,2);size=log.tell();log.seek(max(0,size-65536));tail=log.read()
        complete=tail.splitlines()
        if size>65536:complete=complete[1:]
        for line in complete[-3:]:
            try:parse_line(line.decode('utf-8'),'format-preflight','unpersisted',1)
            except (ValueError,UnicodeError):raise ValueError('Apache combined-only format required before capture') from None
        self.root.mkdir(parents=True)
        write(self.root/'schedule.json',plan)
        for name,path in source_files().items():
            destination=self.root/'generator_source'/name
            destination.parent.mkdir(parents=True,exist_ok=True)
            with destination.open('xb') as out:out.write(path.read_bytes())
        write(self.root/'session.json',{'capture_agent_version':'byte-offset-1.0','server_planned_start_utc':iso(self.clock()),'apache_path':str(self.log)})

    def locked(self):
        handle=(self.root.parent/'.agent.lock').open('a')
        fcntl.flock(handle,fcntl.LOCK_EX)
        return handle

    def begin(self,run_id):
        with self.locked():
            if (self.root/'active.json').exists() or (self.root.parent/'.active_capture.json').exists():raise ValueError('Overlapping capture prohibited')
            plan=json.loads((self.root/'schedule.json').read_text());run=next(r for r in plan['runs'] if r['run_id']==run_id)
            directory=self.root/run_id
            if directory.exists():raise ValueError('Run already exists; no overwrites')
            if any(p.parent.parent!=self.root for p in self.root.parent.glob(f'*/{run_id}/begin.json')):
                raise ValueError('Run ID already attempted in another session; use a reviewed run offset')
            now=self.clock();start=now.replace(microsecond=0)+timedelta(seconds=1)
            self.sleep(max(0,(start-now).total_seconds()))
            # Keep aligned boundaries auditable; fail if clock jumps substantially.
            actual=self.clock()
            if actual<start or (actual-start).total_seconds()>2:raise ValueError('Server clock/alignment bound exceeded')
            with self.log.open('rb') as log:
                stat=os.fstat(log.fileno());offset=stat.st_size
                if offset:
                    log.seek(offset-1)
                    if log.read(1)!=b'\n':raise ValueError('Apache start boundary is an incomplete record')
            directory.mkdir()
            state={'run_id':run_id,'capture_root':str(self.root),'start_utc':iso(actual.replace(microsecond=0)),
                'actual_start_precise_utc':iso(actual),'planned_start_utc':iso(start),
                'planned_end_utc':iso(start+timedelta(seconds=run['duration_seconds'])),
                'device':stat.st_dev,'inode':stat.st_ino,'offset_start':offset,'log_path':str(self.log),
                'parameter_profile_sha256':sha(run)}
            write(directory/'begin.json',state);write(self.root/'active.json',state)
            write(self.root.parent/'.active_capture.json',state)
            return state

    def finish(self,run_id,result):
        with self.locked():
            active=self.root/'active.json'
            state=json.loads(active.read_text())
            if json.loads((self.root.parent/'.active_capture.json').read_text())!=state:raise ValueError('Global capture ownership mismatch')
            if state['run_id']!=run_id:raise ValueError('Active run mismatch')
            plan=json.loads((self.root/'schedule.json').read_text())
            run=next(r for r in plan['runs'] if r['run_id']==run_id)
            validate_result(result,run,plan['context'])
            directory=self.root/run_id
            if (directory/'manifest.json').exists():raise ValueError('Capture already finished')
            self.sleep(2) # Apache completion/flush wait; coordinator adds another two seconds.
            now=self.clock()
            with self.log.open('rb') as log:
                stat=os.fstat(log.fileno())
                if (stat.st_dev,stat.st_ino)!=(state['device'],state['inode']) or stat.st_size<state['offset_start']:raise ValueError('Log rotation/truncation detected; preserve failed capture')
                end=stat.st_size
                if end-state['offset_start']>8*1024*1024:raise ValueError('Unexpected capture size/contamination bound')
                log.seek(state['offset_start']);data=log.read(end-state['offset_start'])
            if data and not data.endswith(b'\n'):raise ValueError('Incomplete Apache end record')
            path=directory/'access.log'
            with path.open('xb') as f:f.write(data)
            import hashlib
            manifest={**state,'end_utc':iso(now.replace(microsecond=0)+timedelta(seconds=1)),
                'actual_end_precise_utc':iso(now),'offset_end':end,'access_file':'access.log',
                'access_sha256':hashlib.sha256(data).hexdigest(),'worker_result':result,
                'capture_boundary_semantics':'Server UTC floor/ceil supports second-resolution Apache timestamps; exact byte offsets define inclusion',
                'status':'CAPTURED_UNVERIFIED'}
            write(directory/'manifest.json',manifest)
            with (directory/'manifest.sha256').open('x') as f:f.write(hashlib.sha256((directory/'manifest.json').read_bytes()).hexdigest()+'\n')
            active.unlink() # Own transient coordination state only; begin/result evidence retained.
            (self.root.parent/'.active_capture.json').unlink()
            return manifest

    def abort(self,run_id):
        with self.locked():
            active=self.root/'active.json';state=json.loads(active.read_text())
            global_path=self.root.parent/'.active_capture.json'
            if state['run_id']!=run_id or json.loads(global_path.read_text())!=state:raise ValueError('Active capture ownership mismatch')
            record={'run_id':run_id,'status':'ABORTED_ACCOUNTING_UNKNOWN','actual_abort_utc':iso(self.clock()),
                    'reason':'Explicit operator abort; begin evidence retained; no usable capture asserted'}
            write(self.root/run_id/'abort.json',record)
            active.unlink();global_path.unlink()
            return record
