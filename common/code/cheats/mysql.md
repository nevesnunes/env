# lifecycle

```sql
CREATE DATABASE DatabaseName;
SHOW DATABASES;

CREATE TABLE table (field1 type1, field2 type2, PRIMARY KEY (field1));
INSERT INTO table1 (field1, field2) VALUES (value1, value2);
```

# debug

```bash
tail /var/log/mysql/error.log

rm /var/lib/mysql/ib_logfile*

mkdir -p /var/run/mysqld
touch /var/run/mysqld/mysqld.sock
chown -R mysql:mysql /var/lib/mysql
mysql_install_db --user=mysql -ldata=/var/lib/mysql/

/etc/init.d/mysql restart
```
