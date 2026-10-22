#!/usr/bin/env python3
# Run with python-dateutil 2.9.0.post0 (pip install python-dateutil==2.9.0.post0):
#   python3 scripts/generate-calendar-recurrence-vectors.py > crates/kutup-crypto/tests/vectors/calendar-recurrence-v1.json
# Generates crates/kutup-crypto/tests/vectors/calendar-recurrence-v1.json:
# RFC 5545 §3.8.5.3 examples in Proton's subset plus Kutup's cases, with
# expected occurrences computed by python-dateutil 2.9.0.post0 (an
# independent RFC 5545 implementation), on the wall clock of DTSTART's zone.
import json, sys
from datetime import datetime, date, timezone
from zoneinfo import ZoneInfo
from dateutil.rrule import rrulestr

CASES = [
  # name, dtstart (local or date), tzid (None: all-day), rule as written, take
  ("rfc daily for 10", "1997-09-02T09:00:00", "America/New_York", "FREQ=DAILY;COUNT=10", 20),
  ("rfc daily until Dec 24", "1997-09-02T09:00:00", "America/New_York", "FREQ=DAILY;UNTIL=19971224T000000Z", 200),
  ("rfc every other day", "1997-09-02T09:00:00", "America/New_York", "FREQ=DAILY;INTERVAL=2", 12),
  ("rfc every 10 days, 5 times", "1997-09-02T09:00:00", "America/New_York", "FREQ=DAILY;INTERVAL=10;COUNT=5", 10),
  ("rfc weekly for 10", "1997-09-02T09:00:00", "America/New_York", "FREQ=WEEKLY;COUNT=10", 20),
  ("rfc every other week", "1997-09-02T09:00:00", "America/New_York", "FREQ=WEEKLY;INTERVAL=2;WKST=SU", 8),
  ("rfc weekly TU TH for five weeks", "1997-09-02T09:00:00", "America/New_York", "FREQ=WEEKLY;UNTIL=19971007T000000Z;WKST=SU;BYDAY=TU,TH", 20),
  ("rfc every other week MO WE FR until Dec 24", "1997-09-01T09:00:00", "America/New_York", "FREQ=WEEKLY;INTERVAL=2;UNTIL=19971224T000000Z;WKST=SU;BYDAY=MO,WE,FR", 40),
  ("rfc every other week TU TH, 8 times", "1997-09-02T09:00:00", "America/New_York", "FREQ=WEEKLY;INTERVAL=2;COUNT=8;WKST=SU;BYDAY=TU,TH", 20),
  ("rfc first Friday, 10 times", "1997-09-05T09:00:00", "America/New_York", "FREQ=MONTHLY;COUNT=10;BYDAY=1FR", 20),
  ("rfc third-to-last day of the month", "1997-09-28T09:00:00", "America/New_York", "FREQ=MONTHLY;BYMONTHDAY=-3", 8),
  ("rfc WKST MO", "1997-08-05T09:00:00", "America/New_York", "FREQ=WEEKLY;INTERVAL=2;COUNT=4;BYDAY=TU,SU;WKST=MO", 10),
  ("rfc WKST SU", "1997-08-05T09:00:00", "America/New_York", "FREQ=WEEKLY;INTERVAL=2;COUNT=4;BYDAY=TU,SU;WKST=SU", 10),
  ("monthly on the 31st skips short months", "2027-01-31", None, "FREQ=MONTHLY;COUNT=6", 10),
  ("leap day yearly", "2028-02-29", None, "FREQ=YEARLY;COUNT=3", 5),
  ("last Friday monthly", "2026-10-30T18:00:00", "Europe/Istanbul", "FREQ=MONTHLY;BYSETPOS=-1;BYDAY=FR", 8),
  ("second Tuesday monthly", "2026-11-10T10:00:00", "Europe/Berlin", "FREQ=MONTHLY;COUNT=6;BYSETPOS=2;BYDAY=TU", 10),
  ("yearly by month", "2026-03-15T08:30:00", "Europe/London", "FREQ=YEARLY;COUNT=4;BYMONTH=3", 10),
  ("yearly by month and day", "2026-12-25", None, "FREQ=YEARLY;COUNT=3;BYMONTHDAY=25;BYMONTH=12", 10),
  ("yearly 100th day", "2027-04-10", None, "FREQ=YEARLY;COUNT=3;BYYEARDAY=100", 10),
  ("yearly last day of the year", "2026-12-31", None, "FREQ=YEARLY;COUNT=3;BYYEARDAY=-1", 10),
  ("daily across Berlin's October change", "2026-10-22T09:00:00", "Europe/Berlin", "FREQ=DAILY;COUNT=7", 10),
  ("weekly in a gap hour (New York, March)", "2027-03-07T02:30:00", "America/New_York", "FREQ=WEEKLY;COUNT=3", 5),
  ("every 3 months", "2026-11-30T12:00:00", "Asia/Tokyo", "FREQ=MONTHLY;INTERVAL=3;COUNT=5", 10),
  ("UTC weekly", "2026-10-23T14:00:00", "UTC", "FREQ=WEEKLY;COUNT=3;BYDAY=MO,FR", 5),
]

def utc_text(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

out = []
for name, start, tzid, rule, take in CASES:
    all_day = tzid is None
    if all_day:
        d = date.fromisoformat(start)
        dtstart = datetime(d.year, d.month, d.day)
    else:
        dtstart = datetime.fromisoformat(start)
    text = rule
    # dateutil needs a naive UNTIL for a naive (wall-clock) DTSTART: the UTC
    # UNTIL as a wall-clock time in DTSTART's zone, as Proton converts it.
    parts = []
    for part in rule.split(";"):
        k, v = part.split("=")
        if k == "UNTIL" and v.endswith("Z"):
            u = datetime.strptime(v, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            v = u.astimezone(ZoneInfo(tzid)).strftime("%Y%m%dT%H%M%S")
        parts.append(f"{k}={v}")
    r = rrulestr(";".join(parts), dtstart=dtstart)
    local = []
    for i, occ in enumerate(r):
        if i >= take or occ.year > 2037:
            break
        local.append(occ)
    case = {"name": name, "rule": rule, "take": take}
    if all_day:
        case["start"] = {"date": start}
        case["local"] = [o.strftime("%Y-%m-%d") for o in local]
    else:
        case["start"] = {"zoned": {"local": start, "tzid": tzid}}
        case["local"] = [o.strftime("%Y-%m-%dT%H:%M:%S") for o in local]
        # RFC 5545 (and jiff's `compatible`): a wall time in a gap or a fold
        # takes the offset before it, which is PEP 495's fold=0.
        z = ZoneInfo(tzid)
        utc = [utc_text(o.replace(tzinfo=z, fold=0)) for o in local]
        case["utc"] = utc
    out.append(case)

json.dump({"version": 1, "generator": "python-dateutil 2.9.0.post0", "cases": out},
          sys.stdout, indent=1, ensure_ascii=False)
print()
