create table FOO_ as select * from FOO;
delete from FOO;
alter index FOO_ID_PK rebuild;
alter table FOO add UNIQUEID NUMBER not null unique;
insert into FOO (select FOO_.*,FOOID as UNIQUEID from FOO_);
commit;
drop table FOO_;
commit;
