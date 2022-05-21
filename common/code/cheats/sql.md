# +

- [SQL Fiddle](http://sqlfiddle.com)
- [Screenshots of our DB Software \- DbVisualizer](https://www.dbvis.com/features/software-screenshots/)
- [How to create a 1M record table with a single query \| Anton Zhiyanov](https://antonz.org/random-table/)

# exploratory

```sql
-- https://severalnines.com/blog/my-favorite-postgresql-queries-and-why-they-matter
SELECT *
FROM alpha AS a
LEFT JOIN bravo AS b
ON b.foo = a.foo
GROUP BY bar, baz
ORDER BY baz NULLS first
LIMIT 10;
```

# window functions, common table expressions

- https://modern-sql.com/blog/2018-04/mysql-8.0
- https://dev.mysql.com/doc/refman/8.0/en/window-function-descriptions.html
- https://dev.mysql.com/doc/refman/8.0/en/with.html

# debug

explain analyze _

- insert/update from database driver not applied in database
    - check if auto-commit on
        - expect: each insert/update in their own transaction => exception in 1st does not affect next ones
        - vs start transaction + ... + commit
        - https://dba.stackexchange.com/questions/27963/postgres-requires-commit-or-rollback-after-exception
    - check if query = INSERT .. ON CONFLICT () DO NOTHING
    - try manual commit in debugger
    - try manual insert/update in external database client

### postgresql

- `pg_stat_statements`: record query performance in table
- `log_min_duration_statement`: if a query takes longer than a specified time, record query in logs
- `auto_explain`: if a query takes longer than a specified time, record the query execution plan in logs

- triggers
    - https://dba.stackexchange.com/questions/233735/track-all-modifications-to-a-postgresql-table
- commented queries: add stackframe to trace back to app source code
    - https://www.crunchydata.com/blog/database-traceability-using-sql-comments

### sqlserver

- SQL Server Profiler
    - SMSS > Tools > SQL Server Profiler
    - https://stackoverflow.com/questions/25836444/how-can-i-see-which-tables-are-changed-in-sql-server
- || Server Side Trace
    - ~/code/snippets/sqlserver/server_side_trace.sql
    - https://www.mssqltips.com/sqlservertip/1035/sql-server-performance-statistics-using-a-server-side-trace/

### generic change audit

- ! take snapshots, binary diff, then parse db format up to closest table name entry, export data for matched tables, diff those tables
    - :) smaller snapshots
    - ./debug.md

# full text search

- https://stackoverflow.com/questions/46122175/fulltext-search-combined-with-fuzzysearch-in-postgresql/51433877#51433877

```sql
drop index if exists idx_search;
create materialized view admin_view as
select
    id,
    number as key,
    concat('Order ', number, ' placed on ',created_at) as description,
    to_tsvector(concat(number,' ',email,' ', name)) as search,
    'order' as type
from orders
UNION
select
    id,
    email as key,
    name as description,
    to_tsvector(concat(name,' ',email)) as search,
    'customer' as type
from customers
UNION
select
    id,
    number as key,
    concat('Invoice ', number, ' created on ',created_at) as description,
    to_tsvector(concat(number,' ',email,' ', name)) as search,
    'invoice' as type
from invoices;

create index idx_search on admin_view using GIN(search);

select id,key,description,type
from admin_view
where search @@ to_tsquery('joe')
order by ts_rank(search,to_tsquery('joe')) desc;
```

# Optimizations

> Could try (nolock) for the SELECT parts or SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED; prior to the CTE to be easier on transactions. (It might also be a terrible idea, depending on the data integrity requirements, YMMV)

# Constraints

- unique constraint creates implicit unique index
    - https://medium.com/flatiron-engineering/uniqueness-in-postgresql-constraints-versus-indexes-4cf957a472fd

# Duplicates

```sql
SELECT *, COUNT(*) AS NoOfOccurrences
FROM TableName GROUP BY *
HAVING COUNT(*) > 1
```

# DDL to XSD/XML schema

```sql
-- sqlserver
DECLARE @schema xml
SET @schema = (SELECT TOP 0 * FROM Person FOR XML AUTO, ELEMENTS, XMLSCHEMA('PersonSchema'))
select @schema

-- postgresql
CREATE OR REPLACE FUNCTION getXml()
  RETURNS xml 
  AS
$BODY$
DECLARE myXml xml;
BEGIN 
    SELECT * INTO myXml FROM query_to_xml_and_xmlschema('SELECT id FROM someTable', true, true, 'myProject.mySchema');
    RETURN myXml;
END;
$BODY$
  LANGUAGE plpgsql VOLATILE
  COST 100;
ALTER FUNCTION getXml() OWNER TO postgres;
SELECT getXml();

-- ||
\o schema_file.xml
select schema_to_xml('public', 't', 't', 'text');
select schema_to_xmlschema('public', 't', 't', 'text');
\o
```

# performance

- ! use exclusion criteria in `where` clause along with intended inclusion criteria

- using functions ignores index and does full table scan

```diff
  SELECT NAME
  FROM Employee
- WHERE YEAR(DOJ) = 2018
+ WHERE DOJ >= '20180101' and DOJ <= '20181231';
```

- http://blogs.lobsterpot.com.au/2010/01/22/sargable-functions-in-sql-server/
- https://github.com/lob/pg_insights

# hierarchies, trees, graphs

- standard sql
- ~/code/doc/databases/Joe Celkos Trees and Hierarchies in SQL for Smarties, Second Edition.pdf
    - 2.4.2. Self-Joins - fixed depth, leafs end in NULL
    - 2.4.3. Recursive CTE
    - 2.4.4. Iterations - use temporary table in procedure
    - 2.7. Leveled - use depth column, find with BFS

### oracle

https://docs.oracle.com/cd/B19306_01/server.102/b14200/queries003.htm

```sql
SELECT employee_id, manager_id, level
FROM employees
START WITH manager_id IS NULL
CONNECT BY PRIOR employee_id = manager_id
```

# backup

```bash
mysqldump --single-transaction --quick --skip-extended-insert \
  --routines -umyuser -pmysecret dbname > /path/to/dumps/dir/dbname.dump;
rdiff-backup /path/to/dumps/dir/ /path/to/backup/dir/
```

https://www.guguweb.com/2020/01/30/mysql-incremental-backup-with-mysqldump-and-rdiff-backup/

# diagrams

https://www.schemacrawler.com/diagramming.html

# Testing

https://github.com/greenplum-db/gpdb/tree/master/src/test/regress/sql

### Default Ports

```
Amazon Redshift | 5439
      GreenPlum | 5432
          MSSQL | 1433
          MySQL | 3306
         Oracle | 1521
     PostgreSQL | 5432
        Vertica | 5433
```

# Oracle SQL

### Fetch all results

On results pane, press: Control-End

### Raw

```sql
DECLARE
    --note that PL/SQL variable is limited to size 32KB
    r RAW(32767);

BEGIN
    r := UTL_RAW.CAST_TO_RAW('Oracle Utilites Book');
    dbms_output.put_line(r);

    r := UTL_ENCODE.BASE64_ENCODE(r);
    dbms_output.put_line(r);

    r := UTL_ENCODE.BASE64_DECODE(r);
    dbms_output.put_line(r);
END;
/
```
### Migrations

- diff table names
- default values
    - e.g. NULL vs '^'
- pseudo-foreign keys
    - e.g. column "id_foo" without constraint
- dos2unix: converting UTF-16LE file foo.sql to UTF-8 Unix format...

```sql
-- Find objects that reference sequences
SELECT OBJECT_NAME(c.object_id) TABLE_NAME,
       c.name COLUMN_NAME,
       dc.name CONSTRAINT_NAME,
       dc.definition [DEFINITION]
FROM sys.columns c
    INNER JOIN sys.default_constraints dc
        ON c.default_object_id = dc.object_id
WHERE dc.definition LIKE '%NEXT VALUE FOR%'
-- ||
SELECT s.object_id AS sequence_object_id,
    s.name AS sequence_name,
    OBJECT_SCHEMA_NAME(o.parent_object_id) + '.'
        + OBJECT_NAME(o.parent_object_id) AS table_name,
    r.*
FROM sys.sequences s
CROSS APPLY sys.dm_sql_referencing_entities(
    OBJECT_SCHEMA_NAME(s.object_id) + '.' + s.name,
    'OBJECT'
) r
JOIN sys.objects o
    ON o.object_id = r.referencing_id

-- Find sequences
SELECT
  name,
  cast(start_value AS NUMERIC)   AS start_value,
  cast(increment AS NUMERIC)     AS increment,
  cast(current_value AS NUMERIC) AS current_value
FROM sys.sequences;

-- Find objects that reference foreign keys
select
    t.name as TableWithForeignKey,
    fk.constraint_column_id as FK_PartNo, c.
    name as ForeignKeyColumn
from
    sys.foreign_key_columns as fk
inner join
    sys.tables as t on fk.parent_object_id = t.object_id
inner join
    sys.columns as c on fk.parent_object_id = c.object_id and fk.parent_column_id = c.column_id
where
    fk.referenced_object_id in (select object_id
                               from sys.tables
                               where name like 'foo_%')
order by
    TableWithForeignKey, FK_PartNo
```

### Output formatting

```
SET FEEDBACK OFF
SET HEADING OFF
SET LINESIZE 32767
SET PAGESIZE 0
SET VERIFY OFF
SET WRAP OFF

spool "c:\sample_table.out";

select /*insert*/ * from sample_table;
-- ||
set sqlformat insert;
select * from sample_table;

spool off;
exit
```

### Dump

```ps1
$env:TNS_ADMIN = "C:\Users\foo\config"
.\expdp.exe 'foo/bar@baz' DIRECTORY=data_dump_dir DUMPFILE=foo.dmp SCHEMAS=foo LOGFILE=database.log
.\exp.exe 'foo/bar@baz' FILE=foo.dmp STATISTICS=NONE FULL=Y

# On EXP-00023: must be a DBA to do Full Database or Tablespace export
.\exp.exe 'foo/bar@baz' FILE=foo.dmp STATISTICS=NONE TABLES='(TBAPP,TBAPPTYPE)'
```

```sql
select table_name from user_tables
-- ||
select table_name from all_tables where owner = 'foo';
```

```
sqlplus /nolog username/password@connect @scriptname

quit;
/
```

script contents:

```sql
spool output.txt
...
spool off
```

### SQL Performance Analyzer

- https://docs.oracle.com/database/121/RATUG/GUID-860FC707-B281-4D81-8B43-1E3857194A72.htm#RATUG166
- http://www.dba-oracle.com/t_callan_sql_performance_analyzer.htm
- http://ksun-oracle.blogspot.com/2013/03/shared-pool-sqla.html

```sql
select * from v$sgainfo;
```

### tracing

```sql
-- http://www.orafaq.com/node/14
-- Watching Your users' every move: All about SQL Tracing

-- unprivileged

set autotrace on
select count(*) from dual;
set autotrace off

-- privileged

alter system set timed_statistics = true;
alter system set sql_trace=true scope=spfile;

select * from v$statistics_level
where statistics_name like 'timed%';

select sid,serial# from v$session
dbms_support.start_trace_in_session(12, 13, waits=>true,binds=>true)
dbms_support.stop_trace_in_session(sid, serial#)
```

# Postgresql

explain (verbose true, analyze true)

# SQL Server

```sql
DBCC FREEPROCCACHE;
DBCC DROPCLEANBUFFERS;

-- Estimated execution plan
SET SHOWPLAN_ALL ON;
SET SHOWPLAN_XML ON;

-- Actual execution plan
SET STATISTICS PROFILE ON;
SET STATISTICS TIME ON;
SET STATISTICS XML ON;

-- Estimated execution plan
SET SHOWPLAN_ALL OFF;
SET SHOWPLAN_XML OFF;

-- Actual execution plan
SET STATISTICS PROFILE OFF;
SET STATISTICS XML OFF;

-- Prefer
Index Seek
Parallelism

-- Avoid
RID Lookup (aka "bookmark lookup")

-- Columns to use in query

CREATE NONCLUSTERED INDEX index_foobar
   ON table_foobar (foo ASC)
   INCLUDE (bar);
-- Use `foo` in where, `bar` in select
-- Don't use other columns
```

### foreign keys

```sql
EXEC sp_help 'foo'

EXEC sp_fkeys @pktable_name = 'foo', @pktable_owner = 'dbo'

select
    t.name as TableWithForeignKey,
    fk.constraint_column_id as FK_PartNo, c.
    name as ForeignKeyColumn
from
    sys.foreign_key_columns as fk
inner join
    sys.tables as t on fk.parent_object_id = t.object_id
inner join
    sys.columns as c on fk.parent_object_id = c.object_id and fk.parent_column_id = c.column_id
where
    fk.referenced_object_id in (select object_id
        from sys.tables
        where name like 'foo_%')
order by
    TableWithForeignKey, FK_PartNo

SELECT
    object_name(parent_object_id) ParentTableName,
    object_name(referenced_object_id) RefTableName,
    name
FROM sys.foreign_keys
```

# SQL Developer

### +

```sql
select
    (select 'foo' from dual),
    count(foo),
    round(count(foo) * 100 / (select count(*) from bar), 2) as p
from bar where nvl(foo, 0) > 0 group by 3 union all
```

### Reset Connection

Connections > DB > Expand

### TNS Directory

Tools > Preferences > Database > Advanced

# SQL Server Management Studio

```sql
SELECT * FROM information_schema.tables WHERE table_name like '%FOO%'

dateadd(day, -30, getdate()),
datediff(day, convert(datetime, '2019-01-26 15:00:00'), d.createdate)

---

SELECT t.[text], s.last_execution_time
FROM sys.dm_exec_cached_plans AS p
INNER JOIN sys.dm_exec_query_stats AS s
   ON p.plan_handle = s.plan_handle
CROSS APPLY sys.dm_exec_sql_text(p.plan_handle) AS t
WHERE t.[text] LIKE N'%foo%'
ORDER BY s.last_execution_time DESC;

SELECT * FROM master.sys.messages
WHERE language_id=1033
AND severity>10;
```

```sql
-- Extended Events (XEvents)
-- https://stackoverflow.com/questions/40847677/sql-server-logging-failed-queries

-- https://stackoverflow.com/questions/7416373/sql-server-query-log-for-failed-incorrect-queries

SELECT * FROM master.sys.messages
 -- language = english
 WHERE language_id=1033
 AND severity > 10;
 --AND message_id=229;

 EXEC sp_altermessage 229, 'WITH_LOG', 'true';

 EXEC xp_readerrorlog 0,1,'permission',NULL,NULL,NULL,'desc'

-- https://dba.stackexchange.com/questions/35015/log-all-errors-in-queries

CREATE EVENT SESSION [ErrorCapture]
ON SERVER
ADD EVENT sqlserver.error_reported
(
    ACTION
    (
        sqlserver.client_hostname,
        sqlserver.database_id,
        sqlserver.sql_text,
        sqlserver.username
    )
    WHERE
    (
        [severity] >= (11)
    )
)
ADD TARGET package0.asynchronous_file_target
(
    SET filename=N'C:\ProgramData\SqlServer-ErrorCapture.xel'
)
WITH
(
    MAX_MEMORY=4096 KB,
    EVENT_RETENTION_MODE=ALLOW_SINGLE_EVENT_LOSS,
    MAX_DISPATCH_LATENCY=30 SECONDS,
    MAX_EVENT_SIZE=0 KB,
    MEMORY_PARTITION_MODE=NONE,
    TRACK_CAUSALITY=OFF,
    STARTUP_STATE=ON
);
GO

ALTER EVENT SESSION [ErrorCapture]
ON SERVER
STATE = START;
GO

-- test

raiserror('This is a test error', 2, 1);
go

-- read

-- https://docs.microsoft.com/en-us/sql/relational-databases/system-functions/sys-fn-xe-file-target-read-file-transact-sql
SELECT * FROM sys.fn_xe_file_target_read_file('C:\ProgramData\SqlServer-ErrorCapture.xel', null, null, null);

-- delete

DROP EVENT SESSION [ErrorCapture] ON SERVER;

---

use msdb;
go

create queue [errors];
go

create service errors on queue [errors] (
    [http://schemas.microsoft.com/SQL/Notifications/PostEventNotification]);
go

create event notification [errors]
    on server for EXCEPTION
    to service N'errors', N'current database';
go

-- test

raiserror('This is a test error', 2, 1);
go

-- read

receive cast(message_body as xml) from errors;
```

# collation

```sql
SELECT name, collation_name
FROM sys.databases
```

- https://dba.stackexchange.com/questions/231087/process-to-change-collation-on-a-database
- https://docs.microsoft.com/en-us/sql/relational-databases/collations/set-or-change-the-server-collation?view=sql-server-2017

- https://ppolyzos.com/2016/12/07/change-sql-server-database/
- https://www.mssqltips.com/sqlservertip/3519/changing-sql-server-collation-after-installation/

- https://stackoverflow.com/questions/6296936/can-sql-server-sql-latin1-general-cp1-ci-as-be-safely-converted-to-latin1-genera
    - SQL_Latin1_General_CP1_CI_AS => `ß` is not expanded to `ss`.

- comparing diff collations
    ```sql
    WHERE Col1 COLLATE SQL_Latin1_General_CP1_CS_AS
          = Col2 COLLATE SQL_Latin1_General_CP1_CS_AS
    -- ||
    WHERE Col1 = Col2 COLLATE DATABASE_DEFAULT
    ```

# indexes

https://hackernoon.com/clustered-vs-nonclustered-what-index-is-right-for-my-data-717b329d042c

# return generated sequence id

### sql server

```sql
INSERT INTO table (name)
    OUTPUT Inserted.ID
    VALUES('bob');
```

### oracle sql

```sql
insert into your_tab (col1, col2, col3)
    values (some_seq_val, val2, val3)
    returning some_seq_val into lv_seq;
```

[How do I list all tables in a schema in Oracle SQL? \- Stack Overflow](https://stackoverflow.com/a/2247758)

### jdbc

```java
String sql = "INSERT INTO tbl (col) VALUES (?)";
preparedStatement = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
preparedStatement.setString(1, col);
preparedStatement.executeUpdate();
generatedKeys = preparedStatement.getGeneratedKeys();
if (generatedKeys.next()) {
    long id = generatedKeys.getLong(1);
} else {
    // Throw exception?
}
```

### mybatis

```xml
<insert id="createEmpty" parameterType="Project" useGeneratedKeys="true" keyProperty="projectId" keyColumn="PROJECT_ID">
    INSERT INTO PROJECT (TITLE,DESCRIPTION)
    VALUES
    (#{title},#{description})
</insert>
```

```java
projectRepository.createEmpty(p, "one", "two");
p.getProjectId();
```

# Automatic Memory Management

https://docs.oracle.com/cd/B28359_01/server.111/b28310/memory003.htm#ADMIN11011

# update if exists

https://stackoverflow.com/questions/10589350/oracle-db-equivalent-of-on-duplicate-key-update

# having

= filter aggregate columns

# combine results

- union all
- subquery
- coalesce columns
    - https://stackoverflow.com/questions/2360396/how-can-i-merge-the-columns-from-two-tables-into-one-output

# case studies

### length operator loads full blob data

- [Michael Lynch on Twitter: \"I had an interesting time investigating a bug related to SQLite performance today, so I thought I'd share a thread. A PicoShare user reported that it took 14.57 seconds to load their list of files.\"](https://twitter.com/deliberatecoder/status/1520399221291163648)
    - analysis: files stored as blobs, test with large file, replace `sum(length(data))` by `sum(1)` removes bottleneck
    - attempt 1: storing chunk size in entries table, still slow due to chunk data filling most of the pages
        - https://www.sqlite.org/fileformat2.html
    - attempt 2: storing chunk size in metadata table, better performance 
        - https://github.com/mtlynch/picoshare/pull/221
    - attempt 3: creating index on `entries_data(id, LENGTH(chunk))`, query on `SUM(LENGTH(chunk))`, avoids storing size redundantly
        - https://github.com/mtlynch/picoshare/pull/230

### avoid overbooking

- if using multiple statements:
    - set isolation level to avoid dirty reads
        - http://en.wikipedia.org/wiki/Isolation_%28database_systems%29#READ_UNCOMMITTED_.28dirty_reads.29
    - use `start transaction` to rollback
        - https://dev.mysql.com/doc/refman/8.0/en/commit.html
- reservation between dates
    ```
    -- OK
    A_in >= B_out OR A_out <= B_in
    -- De Morgan's law: NOT (x OR y) = NOT(x) AND NOT(y)
    -- CONFLICT
    A_in < B_out AND A_out > B_in
    ```
- long processing times (e.g. third-party payment)
    - hold reservations before collecting payment info
    - use status flag to signal processing of reservation, set status with transactions, configured with timeout
- "underhanded sql contest"
    - no query error
    - no @@ROWCOUNT check
    - if users are shown free rooms with a previously run select, this update will cause overbooking
        ```sql
        UPDATE table
        SET status = "reserved"
        WHERE room_id = "asked_id"
        AND status = "free";
        ```
- https://dba.stackexchange.com/questions/158316/strategy-for-concurrent-group-bookings
