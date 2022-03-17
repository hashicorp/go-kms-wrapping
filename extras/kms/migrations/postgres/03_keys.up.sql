begin;

create or replace function
  kms_root_key_version_column()
  returns trigger
as $$
begin
  update kms_root_key_version set version =
  (
    select max(coalesce(version,1)) + 1 
    from kms_root_key_version 
    where 
      data_key_id = new.data_key_id 
  )
  where rowid = new.rowid;  
end;
$$ language plpgsql;
comment on function
  kms_root_key_version_column()
is
  'function used in before insert trigger on kms_root_key_version to properly set version column';


create or replace function
  kms_data_key_version_column()
  returns trigger
as $$
begin
  update kms_data_key_version set version =
  (
    select max(coalesce(version,1)) + 1 
    from kms_data_key_version 
    where 
      data_key_id = new.data_key_id and  
      purpose = new.purpose
  )
  where rowid = new.rowid;  
end;
$$ language plpgsql;
comment on function
  kms_data_key_version_column()
is
  'function used in before insert trigger on kms_data_key_version to properly set version column';

commit;