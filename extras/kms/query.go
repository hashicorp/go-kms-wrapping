// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kms

const (
	postgresForeignReferencersQuery = `
select distinct
	r.table_name
from
	information_schema.constraint_column_usage            u
	inner join information_schema.referential_constraints fk
		on u.constraint_catalog = fk.unique_constraint_catalog
			and u.constraint_schema = fk.unique_constraint_schema
			and u.constraint_name = fk.unique_constraint_name
	inner join information_schema.key_column_usage        r
		on r.constraint_catalog = fk.constraint_catalog
			and r.constraint_schema = fk.constraint_schema
			and r.constraint_name = fk.constraint_name
where
	u.column_name = 'private_id' and
	u.table_name = 'kms_data_key_version'
`
	sqliteForeignReferencersQuery = `
select 
	m.name
from
	sqlite_master m
	join pragma_foreign_key_list(m.name) p on m.name != p."table"
where 
	m.type = 'table' and
	p."table" = 'kms_data_key_version' and
	p."to" = 'private_id'
`
	scopesMissingDataKeyQuery = `
  select scp.purpose,
         scp.scope_id
    from (select s.id      as scope_id,
                 p.purpose as purpose
            from unnest($1::text[])   as s(id)
                 cross join unnest($2::text[]) as p(purpose)
         ) as scp
         left join %s_root_key as rk
           on rk.scope_id = scp.scope_id
         left join %s_data_key as dk
           on dk.root_key_id = rk.private_id
              and dk.purpose = scp.purpose
   where dk.private_id is null
order by scp.purpose,
         scp.scope_id
`
)
