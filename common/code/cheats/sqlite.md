sqlite3 foo.sqlite .dump | vim -

.mode list
.output out.txt
.read in.sql

# columns

.schema foo
PRAGMA table_info('foo')

# iphone

select znb.zcontent from znotebody znb;
select ci.summary, ci.description from CalendarItem ci;
select ci.summary, ci.description from CalendarItem ci where creation_date is not null;
select ci.summary, ci.description from CalendarItem ci where external_mode_tag is not null;
select ci.summary, ci.description from CalendarItem ci where last_modified is not (select max(last_modified) from CalendarItem);

select
'ROWID',
count(distinct ROWID),
...
from CalendarItem;
