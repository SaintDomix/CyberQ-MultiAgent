"""Append-only binary reader. Rotation/truncation never reset the cursor."""
import hashlib
import os
from pathlib import Path
import stat
from .live_storage import IntegrityFault

MAX_LINE=262144
MAX_POLL=4*1024*1024


def anchor(handle,offset):
    start=max(0,offset-4096);handle.seek(start)
    return {'offset':offset,'start':start,'sha256':hashlib.sha256(handle.read(offset-start)).hexdigest()}


class AppendReader:
    def __init__(self,path,state=None):
        self.path=Path(path).resolve()
        with self.path.open('rb') as handle:
            current=os.fstat(handle.fileno())
            if not stat.S_ISREG(current.st_mode):raise IntegrityFault('SOURCE_NOT_REGULAR_FILE')
            if state:
                offsets=[state[k] for k in ('initial_offset','safe_offset','read_offset','observed_size')]
                if any(isinstance(v,bool) or not isinstance(v,int) or v<0 for v in offsets) or offsets!=sorted(offsets):raise IntegrityFault('SOURCE_OFFSET_STATE_INVALID')
                if str(self.path)!=state['path'] or (current.st_dev,current.st_ino)!=(state['device'],state['inode']):raise IntegrityFault('SOURCE_IDENTITY_CHANGED')
                if current.st_size<state['observed_size']:raise IntegrityFault('SOURCE_TRUNCATED')
                for saved in state['anchors']:
                    if anchor(handle,saved['offset'])!=saved:raise IntegrityFault('SOURCE_CONTINUITY_CHANGED')
                cursor=state['safe_offset'];skip=state['skip_partial']
            else:
                cursor=current.st_size
                handle.seek(max(0,cursor-1));skip=bool(cursor and handle.read(1)!=b'\n')
            self.device=current.st_dev;self.inode=current.st_ino;self.observed_size=current.st_size
            self.initial_offset=state['initial_offset'] if state else cursor
            self.initial_anchor=state['anchors'][0] if state else anchor(handle,cursor)
            self.position=(cursor,anchor(handle,cursor),skip)  # Atomic signal-safe position update.
            highwater=state['read_offset'] if state else cursor
            self.highwater_state=(highwater,anchor(handle,highwater))
        self.drained=False;self.partial=False;self.replay_guard=None

    @property
    def cursor(self):return self.position[0]

    @property
    def skip_partial(self):return self.position[2]

    @property
    def highwater(self):return self.highwater_state[0]

    @property
    def highwater_anchor(self):return self.highwater_state[1]

    def ack(self):self.replay_guard=None

    def poll(self):
        records=[]
        # Remains until the caller acknowledges the entire returned batch. Ctrl+C
        # between read and parsing must not checkpoint past unprocessed records.
        self.replay_guard=(self.cursor,self.skip_partial)
        with self.path.open('rb') as handle:
            self._check(handle)
            cursor=self.cursor;skip=self.skip_partial
            handle.seek(cursor);raw=handle.read(MAX_POLL)
            self.partial=bool(raw and not raw.endswith(b'\n'))
            end=raw.rfind(b'\n')+1
            if end==0 and len(raw)>MAX_LINE:raise IntegrityFault('SOURCE_LINE_BOUND_EXCEEDED')
            for part in raw[:end].split(b'\n')[:-1]:
                line=part+b'\n'
                if len(line)>MAX_LINE:raise IntegrityFault('SOURCE_LINE_BOUND_EXCEEDED')
                start=cursor;cursor+=len(line)
                records.append((start,cursor,line,skip));skip=False
            self._check(handle)
            new_anchor=anchor(handle,cursor)
            if cursor>self.highwater:
                self.highwater_state=(cursor,new_anchor)
            self.position=(cursor,new_anchor,skip)
            self.drained=cursor==self.observed_size
        return records

    def _check(self,handle):
        current=os.fstat(handle.fileno());named=self.path.stat()
        if (current.st_dev,current.st_ino)!=(self.device,self.inode) or (named.st_dev,named.st_ino)!=(self.device,self.inode):raise IntegrityFault('SOURCE_ROTATED')
        if current.st_size<self.observed_size or current.st_size<self.cursor:raise IntegrityFault('SOURCE_TRUNCATED')
        if anchor(handle,self.initial_offset)!=self.initial_anchor or anchor(handle,self.cursor)!=self.position[1] or anchor(handle,self.highwater)!=self.highwater_anchor:raise IntegrityFault('SOURCE_CONTINUITY_CHANGED')
        self.observed_size=current.st_size

    def state(self,safe_offset):
        with self.path.open('rb') as handle:
            self._check(handle)
            skip=self.replay_guard[1] if self.replay_guard and safe_offset==self.replay_guard[0] else self.skip_partial
            return {'path':str(self.path),'device':self.device,'inode':self.inode,'safe_offset':safe_offset,
                    'read_offset':max(self.cursor,self.highwater),'observed_size':self.observed_size,'initial_offset':self.initial_offset,
                    'skip_partial':skip,'anchors':[self.initial_anchor,anchor(handle,safe_offset),anchor(handle,max(self.cursor,self.highwater))]}
