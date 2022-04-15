begin;

create table kms_schema_version(
    version text not null,
    create_time kms_timestamp,
    update_time kms_timestamp
);

-- ensure that it's only ever one row
create unique index kms_schema_version_one_row
ON kms_schema_version((version is not null));

 -- define the immutable fields for kms_root_key (all of them)
create trigger kms_immutable_columns
before
update on kms_schema_version
  for each row execute procedure kms_immutable_columns('create_time');

create trigger kms_default_create_time_column
before
insert on kms_schema_version
  for each row execute procedure kms_default_create_time();

create trigger update_time_column 
before 
update on kms_schema_version 
	for each row execute procedure update_time_column();

insert into kms_schema_version(version) values('v0.0.1');

commit;