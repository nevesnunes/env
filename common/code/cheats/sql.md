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

https://modern-sql.com/blog/2018-04/mysql-8.0
https://dev.mysql.com/doc/refman/8.0/en/window-function-descriptions.html
https://dev.mysql.com/doc/refman/8.0/en/with.html

# debug

explain analyze _

# full text search

https://stackoverflow.com/questions/46122175/fulltext-search-combined-with-fuzzysearch-in-postgresql/51433877#51433877

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

Could try (nolock) for the SELECT parts or SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED; prior to the CTE to be easier on transactions. (It might also be a terrible idea, depending on the data integrity requirements, YMMV)

# Constraints

unique constraint creates implicit unique index
    https://medium.com/flatiron-engineering/uniqueness-in-postgresql-constraints-versus-indexes-4cf957a472fd

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

https://github.com/lob/pg_insights

# Oracle SQL

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

### Dump

$env:TNS_ADMIN = "C:\Users\foo\config"
.\expdp.exe 'foo_db/foo_user@foo_host' DIRECTORY=data_dump_dir DUMPFILE=foo_db.dmp SCHEMAS=foo_db LOGFILE=database.log
.\exp.exe 'foo_db/foo_user@foo_host' FILE=foo_db.dmp STATISTICS=NONE FULL=Y
-- [if] EXP-00023: must be a DBA to do Full Database or Tablespace export
.\exp.exe 'foo_db/foo_user@foo_host' FILE=foo_db.dmp STATISTICS=NONE TABLES='(TBAPP,TBAPPTYPE)'

select table_name from user_tables
-- ||
select table_name from all_tables where owner = 'foo_db';

```
sqlplus /nolog username/password@connect @scriptname 

quit;
/
```

### SQL Performance Analyzer

https://docs.oracle.com/database/121/RATUG/GUID-860FC707-B281-4D81-8B43-1E3857194A72.htm#RATUG166
http://www.dba-oracle.com/t_callan_sql_performance_analyzer.htm
http://ksun-oracle.blogspot.com/2013/03/shared-pool-sqla.html

select * from v$sgainfo;

### tracing

```
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
==> Use `foo` in where, `bar` in select
==> Don't use other columns

### foreign keys

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

# SQL Developer

### +

```
select 
    (select 'HIRPTEMA' from dual), 
    count(HIRPTEMA), 
    round(count(HIRPTEMA) * 100 / (select count(*) from taighirp), 2) as p
from taighirp where nvl(HIRPTEMA, 0) > 0 group by 3 union all
...
```

### Reset Connection

Connections > DB > Expand

### TNS Directory

Tools > Preferences > Database > Advanced

# SQL Server Management Studio

```
SELECT * FROM information_schema.tables WHERE table_name like '%TCNT%'

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

---

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
    SET filename=N'C:\ErrorCapture.xel'
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

raiserror('This is a test error', 2, 1);

-- https://docs.microsoft.com/en-us/sql/relational-databases/system-functions/sys-fn-xe-file-target-read-file-transact-sql
SELECT * FROM sys.fn_xe_file_target_read_file('C:\ErrorCapture.xel', 'C:\ErrorCapture.xem', null, null);

DROP EVENT SESSION [ErrorCapture] ON SERVER;
```

# collation

SELECT name, collation_name
FROM sys.databases

https://dba.stackexchange.com/questions/231087/process-to-change-collation-on-a-database
https://docs.microsoft.com/en-us/sql/relational-databases/collations/set-or-change-the-server-collation?view=sql-server-2017

https://ppolyzos.com/2016/12/07/change-sql-server-database/
https://www.mssqltips.com/sqlservertip/3519/changing-sql-server-collation-after-installation/

https://stackoverflow.com/questions/6296936/can-sql-server-sql-latin1-general-cp1-ci-as-be-safely-converted-to-latin1-genera
    SQL_Latin1_General_CP1_CI_AS => `ß` is not expanded to `ss`.

comparing diff collations
    ```
    WHERE Col1 COLLATE SQL_Latin1_General_CP1_CS_AS
          = Col2 COLLATE SQL_Latin1_General_CP1_CS_AS
    ||
    WHERE Col1 = Col2 COLLATE DATABASE_DEFAULT
    ```

# indexes

https://hackernoon.com/clustered-vs-nonclustered-what-index-is-right-for-my-data-717b329d042c

# return generated sequence id

### sql server

INSERT INTO table (name)
    OUTPUT Inserted.ID
    VALUES('bob');

### oracle sql

insert into your_tab (col1, col2, col3) 
    values (some_seq_val, val2, val3) 
    returning some_seq_val into lv_seq;

https://stackoverflow.com/a/2247758

### jdbc

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

### mybatis

<insert id="createEmpty" parameterType="Project" useGeneratedKeys="true" keyProperty="projectId" keyColumn="PROJECT_ID">
    INSERT INTO PROJECT (TITLE,DESCRIPTION)
    VALUES
    (#{title},#{description})
</insert>

projectRepository.createEmpty(p, "one", "two");
p.getProjectId() + "\n";

# Automatic Memory Management

https://docs.oracle.com/cd/B28359_01/server.111/b28310/memory003.htm#ADMIN11011

# update if exists

https://stackoverflow.com/questions/10589350/oracle-db-equivalent-of-on-duplicate-key-update
