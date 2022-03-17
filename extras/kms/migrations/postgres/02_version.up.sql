begin;

create table kms_version(
    version text not null,
    create_time wt_timestamp,
    update_time wt_timestamp
);

-- ensure that it's only ever one row
create unique index kms_version_one_row
ON kms_version((version is not null));

 -- define the immutable fields for kms_root_key (all of them)
create trigger 
  immutable_columns
before
update on kms_version
  for each row execute procedure immutable_columns('create_time');

create trigger 
  default_create_time_column
before
insert on kms_version
  for each row execute procedure default_create_time();

create trigger update_time_column 
before 
update on kms_version 
	for each row execute procedure update_time_column();

insert into kms_version(version) values('v0.0.1');

commit;