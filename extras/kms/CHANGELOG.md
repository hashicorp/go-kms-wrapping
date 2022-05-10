# kms package CHANGELOG

Canonical reference for changes, improvements, and bugfixes for the kms package.

## Bug fixes
* Explicitly naming FK and unique constraints so they can be referenced by name
  in the future if any changes are required. Add the `kms` prefix to the
  `update_time_column()` function. 
  ([PR](https://github.com/hashicorp/go-kms-wrapping/pull/88)).

  The decision was made to make these changes by modifying existing migrations,
  so if you've already installed this package, you'll need to review the PR and
  make the changes by hand in a new migration.



