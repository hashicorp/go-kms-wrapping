begin;

create table kms_root_key (
  private_id kms_private_id primary key,
  scope_id kms_scope_id not null unique, -- there can only be one root key for a scope.
  create_time kms_timestamp
);
comment on table kms_root_key is
  'kms_root_key defines a root key for a scope';

 -- define the immutable fields for kms_root_key (all of them)
create trigger kms_immutable_columns
before
update on kms_root_key
  for each row execute procedure kms_immutable_columns('private_id', 'scope_id', 'create_time');

create trigger kms_default_create_time_column
before
insert on kms_root_key
  for each row execute procedure kms_default_create_time();

create table kms_root_key_version (
  private_id kms_private_id primary key,
  root_key_id kms_private_id not null
    references kms_root_key(private_id) 
    on delete cascade 
    on update cascade,
  version kms_version,
  key bytea not null,
  create_time kms_timestamp,
  unique(root_key_id, version)
);
comment on table kms_root_key_version is
  'kms_root_key_version contains versions of a kms_root_key';

-- define the immutable fields for kms_root_key_version (all of them)
create trigger kms_immutable_columns
before
update on kms_root_key_version
  for each row execute procedure kms_immutable_columns('private_id', 'root_key_id', 'version', 'key', 'create_time');

create trigger kms_default_create_time_column
before
insert on kms_root_key_version
  for each row execute procedure kms_default_create_time();


create trigger kms_version_column
before insert on kms_root_key_version
  for each row execute procedure kms_version_column('root_key_id');


create table kms_data_key (
  private_id kms_private_id primary key,
  root_key_id kms_private_id not null
    references kms_root_key(private_id)
    on delete cascade
    on update cascade,
  purpose text not null unique
    constraint not_empty_purpose
    check (
      length(trim(purpose)) > 0
    ),
  create_time kms_timestamp,
  unique (root_key_id, purpose) -- there can only be one dek for a specific purpose per root key
);
comment on table kms_data_key is
  'kms_data_key contains deks (data keys) for specific purposes derived from a kms_root_key';

 -- define the immutable fields for kms_data_key (all of them)
create trigger kms_immutable_columns
before
update on kms_data_key
  for each row execute procedure kms_immutable_columns('private_id', 'root_key_id', 'purpose', 'create_time');

create trigger kms_default_create_time_column
before
insert on kms_data_key
  for each row execute procedure kms_default_create_time();

create table kms_data_key_version (
  private_id kms_private_id primary key,
  data_key_id kms_private_id not null
    references kms_data_key(private_id) 
    on delete cascade 
    on update cascade, 
  root_key_version_id kms_private_id not null
    references kms_root_key_version(private_id) 
    on delete cascade 
    on update cascade,
  version kms_version,
  key bytea not null,
  create_time kms_timestamp,
  unique(data_key_id, version)
);
comment on table kms_data_key is
  'kms_data_key_version contains versions of a kms_data_key (dek aka data keys)';

 -- define the immutable fields for kms_data_key_version (all of them)
create trigger kms_immutable_columns
before
update on kms_data_key_version
  for each row execute procedure kms_immutable_columns('private_id', 'data_key_id', 'root_key_version_id', 'version', 'key', 'create_time');
  
create trigger kms_default_create_time_column
before
insert on kms_data_key_version
  for each row execute procedure kms_default_create_time();

create trigger kms_version_column
before insert on kms_data_key_version
	for each row execute procedure kms_version_column('data_key_id');

commit;