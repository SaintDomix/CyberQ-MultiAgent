"""Nonempty UTC epoch-aligned fixed windows, keyed by run/client/UA digest."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from .events import identifier


def windows(events, seconds=10):
    if isinstance(seconds,bool) or not isinstance(seconds,int) or seconds < 1: raise ValueError('Positive integer window required')
    groups=defaultdict(list)
    for event in events:
        # Integer microseconds avoid float boundary rounding.
        delta=event.timestamp.astimezone(timezone.utc)-datetime(1970,1,1,tzinfo=timezone.utc)
        micros=(delta.days*86400+delta.seconds)*1000000+delta.microseconds
        tick=micros//(seconds*1000000)*seconds
        groups[(tick,event.client_id,identifier(event.user_agent) or 'missing')].append(event)
    for (tick,client,agent),group in sorted(groups.items()):
        start=datetime.fromtimestamp(tick,timezone.utc)
        yield {'window_start':start.isoformat(),'window_end':(start+timedelta(seconds=seconds)).isoformat(),
               'client_id':client,'user_agent_id':agent,'events':sorted(group,key=lambda e:(e.timestamp,e.source_file,e.line_number))}
