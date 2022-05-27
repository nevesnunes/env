# +

- [sqlite3 fiddle](https://sqlite.org/fiddle/)

```bash
sqlite3 foo.db .dump | vim -
echo 'select * from sqlite_master;' | sqlite3 foo.db | vim -
```

```
.mode list
.output out.txt
.read in.sql
```

```sql
-- list tables / schemas
SELECT name, sql FROM sqlite_master WHERE type='table'
```

# csv

```
.mode csv
.import foo.csv foo
```

```bash
sqlite3 -header -csv foo.db < query.sql > data.csv
```

# columns

```
.schema foo
PRAGMA table_info('foo')
```

# diff

- https://www.sqlite.org/sqldiff.html

# iphone

```sql
select znb.zcontent from znotebody znb;
select ci.summary, ci.description from CalendarItem ci;
select ci.summary, ci.description from CalendarItem ci where creation_date is not null;
select ci.summary, ci.description from CalendarItem ci where external_mode_tag is not null;
select ci.summary, ci.description from CalendarItem ci where last_modified is not (select max(last_modified) from CalendarItem);

select
'ROWID',
count(distinct ROWID)
from CalendarItem;
```
