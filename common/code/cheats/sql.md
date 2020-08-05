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

insert/update from database driver not applied in database
    check if auto-commit on
        expect: each insert/update in their own transaction => exception in 1st does not affect next ones
        vs start transaction + ... + commit
        https://dba.stackexchange.com/questions/27963/postgres-requires-commit-or-rollback-after-exception
    check if query = INSERT .. ON CONFLICT () DO NOTHING
    try manual commit in debugger
    try manual insert/update in external database client

### postgresql

triggers
    https://dba.stackexchange.com/questions/233735/track-all-modifications-to-a-postgresql-table

### sqlserver

SQL Server Profiler
    SMSS > Tools > SQL Server Profiler
    https://stackoverflow.com/questions/25836444/how-can-i-see-which-tables-are-changed-in-sql-server
|| Server Side Trace
    ~/code/snippets/sqlserver/server_side_trace.sql
    https://www.mssqltips.com/sqlservertip/1035/sql-server-performance-statistics-using-a-server-side-trace/

### generic change audit

! take snapshots, binary diff, then parse db format up to closest table name entry, export data for matched tables, diff those tables
    :) smaller snapshots
    ./debug.md

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

! use exclusion criteria in `where` clause along with intended inclusion criteria

using functions ignores index and does full table scan
```diff
  SELECT NAME
  FROM Employee
- WHERE YEAR(DOJ) = 2018
+ WHERE DOJ >= '20180101' and DOJ <= '20181231';
```
http://blogs.lobsterpot.com.au/2010/01/22/sargable-functions-in-sql-server/

https://github.com/lob/pg_insights

# hierarchies, trees, graphs

standard sql
~/code/doc/databases/Joe Celkos Trees and Hierarchies in SQL for Smarties, Second Edition by Joe Celko (z-lib.org).pdf
    2.4.2. Self-Joins - fixed depth, leafs end in NULL
    2.4.3. Recursive CTE
    2.4.4. Iterations - use temporary table in procedure
    2.7. Leveled - use depth column, find with BFS

oracle
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
