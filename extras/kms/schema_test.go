// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kms

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-dbw"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootKey_ScopeId(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	db, _ := TestDb(t)
	rw := dbw.New(db)
	testScopeId := "o_1234567890"
	_ = testRootKey(t, db, testScopeId)

	k, err := newRootKey(testScopeId)
	require.NoError(err)
	id, err := dbw.NewId(rootKeyPrefix)
	require.NoError(err)
	k.PrivateId = id
	k.tableNamePrefix = DefaultTableNamePrefix
	err = rw.Create(context.Background(), k, dbw.WithTable(k.TableName()))
	assert.Error(err)
	assert.Contains(strings.ToLower(err.Error()), "unique")
}

func TestRootKeyVersion_ImmutableFields(t *testing.T) {
	t.Parallel()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))

	testScopeId := "o_1234567890"
	rk := testRootKey(t, db, testScopeId)
	new, _ := testRootKeyVersion(t, db, wrapper, rk.PrivateId)

	tests := []struct {
		name      string
		update    *rootKeyVersion
		fieldMask []string
	}{
		{
			name:      "private_id",
			update:    new.Clone(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create_time",
			update: func() *rootKeyVersion {
				k := new.Clone()
				k.CreateTime = time.Now()
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "root_key_id",
			update: func() *rootKeyVersion {
				k := new.Clone()
				k.RootKeyId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.Clone()
			orig.tableNamePrefix = DefaultTableNamePrefix
			err := rw.LookupBy(context.Background(), orig, dbw.WithTable(orig.TableName()))
			require.NoError(err)

			err = tc.update.Encrypt(context.Background(), wrapper)
			require.NoError(err)
			rowsUpdated, err := rw.Update(context.Background(), tc.update, tc.fieldMask, nil)
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			after.tableNamePrefix = DefaultTableNamePrefix
			err = rw.LookupBy(context.Background(), after, dbw.WithTable(after.TableName()))
			require.NoError(err)

			assert.Equal(orig, after)
		})
	}
}

func TestRootKey_ImmutableFields(t *testing.T) {
	t.Parallel()
	db, _ := TestDb(t)
	rw := dbw.New(db)

	testScopeId := "o_1234567890"
	new := testRootKey(t, db, testScopeId)

	tests := []struct {
		name      string
		update    *rootKey
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *rootKey {
				k := new.Clone()
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create_time",
			update: func() *rootKey {
				k := new.Clone()
				k.CreateTime = time.Now()
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "scope_id",
			update: func() *rootKey {
				k := new.Clone()
				k.ScopeId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"ScopeId"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.Clone()
			orig.tableNamePrefix = DefaultTableNamePrefix
			err := rw.LookupBy(context.Background(), orig, dbw.WithTable(orig.TableName()))
			require.NoError(err)

			rowsUpdated, err := rw.Update(context.Background(), tc.update, tc.fieldMask, nil)
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			after.tableNamePrefix = DefaultTableNamePrefix
			err = rw.LookupBy(context.Background(), after, dbw.WithTable(after.TableName()))
			require.NoError(err)

			assert.Equal(orig, after)
		})
	}
}

func TestDataKey_ImmutableFields(t *testing.T) {
	t.Parallel()
	db, _ := TestDb(t)
	rw := dbw.New(db)

	testScopeId := "o_1234567890"
	rk := testRootKey(t, db, testScopeId)
	new := testDataKey(t, db, rk.PrivateId, "test")

	tests := []struct {
		name      string
		update    *dataKey
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *dataKey {
				k := new.Clone()
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create_time",
			update: func() *dataKey {
				k := new.Clone()
				k.CreateTime = time.Now()
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "root_key_id",
			update: func() *dataKey {
				k := new.Clone()
				k.RootKeyId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "purpose",
			update: func() *dataKey {
				k := new.Clone()
				k.Purpose = "changed"
				return k
			}(),
			fieldMask: []string{"Purpose"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			new.tableNamePrefix = DefaultTableNamePrefix
			orig := new.Clone()
			err := rw.LookupBy(context.Background(), orig, dbw.WithTable(orig.TableName()))
			require.NoError(err)

			rowsUpdated, err := rw.Update(context.Background(), tc.update, tc.fieldMask, nil)
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupBy(context.Background(), after, dbw.WithTable(after.TableName()))
			require.NoError(err)

			assert.Equal(orig, after)
		})
	}
}

func TestDataKeyVersion_ImmutableFields(t *testing.T) {
	t.Parallel()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))

	testScopeId := "o_1234567890"
	rk := testRootKey(t, db, testScopeId)
	_, rkvWrapper := testRootKeyVersion(t, db, wrapper, rk.PrivateId)

	dk := testDataKey(t, db, rk.PrivateId, "test")
	new := testDataKeyVersion(t, db, rkvWrapper, dk.PrivateId, []byte("data-key"))

	tests := []struct {
		name      string
		update    *dataKeyVersion
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *dataKeyVersion {
				k := new.Clone()
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create_time",
			update: func() *dataKeyVersion {
				k := new.Clone()
				k.CreateTime = time.Now()
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "data_key_id",
			update: func() *dataKeyVersion {
				k := new.Clone()
				k.DataKeyId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "root_key_version_id",
			update: func() *dataKeyVersion {
				k := new.Clone()
				k.RootKeyVersionId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			new.tableNamePrefix = DefaultTableNamePrefix
			orig := new.Clone()
			err := rw.LookupBy(context.Background(), orig, dbw.WithTable(orig.TableName()))
			require.NoError(err)

			err = tc.update.Encrypt(context.Background(), wrapper)
			require.NoError(err)
			rowsUpdated, err := rw.Update(context.Background(), tc.update, tc.fieldMask, nil)
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupBy(context.Background(), after, dbw.WithTable(after.TableName()))
			require.NoError(err)

			assert.Equal(orig, after)
		})
	}
}

func TestRootKey_Version(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	testCtx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))

	testScopeId := "o_1234567890"
	rk := testRootKey(t, db, testScopeId)
	rkv1, _ := testRootKeyVersion(t, db, wrapper, rk.PrivateId)
	assert.Equal(uint32(1), rkv1.Version)

	found := &rootKeyVersion{
		PrivateId:       rkv1.PrivateId,
		tableNamePrefix: DefaultTableNamePrefix,
	}
	require.NoError(rw.LookupBy(testCtx, found, dbw.WithTable(found.TableName())))
	found.Decrypt(testCtx, wrapper)
	assert.Equal(rkv1, found)

	rkv2, _ := testRootKeyVersion(t, db, wrapper, rk.PrivateId)
	assert.Equal(uint32(2), rkv2.Version)
}

func TestDataKey_Version(t *testing.T) {
	t.Run("test-version-trigger", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		testCtx := context.Background()
		db, _ := TestDb(t)
		rw := dbw.New(db)
		wrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))

		testScopeId := "o_1234567890"
		rk := testRootKey(t, db, testScopeId)
		_, rkvWrapper := testRootKeyVersion(t, db, wrapper, rk.PrivateId)

		dk := testDataKey(t, db, rk.PrivateId, "test")

		dkv1 := testDataKeyVersion(t, db, rkvWrapper, dk.PrivateId, []byte("data-key-1"))
		assert.Equal(uint32(1), dkv1.Version)

		found := &dataKeyVersion{
			PrivateId:       dkv1.PrivateId,
			tableNamePrefix: DefaultTableNamePrefix,
		}
		require.NoError(rw.LookupBy(testCtx, found, dbw.WithTable(found.TableName())))
		found.Decrypt(testCtx, wrapper)
		assert.Equal(dkv1, found)

		dkv2 := testDataKeyVersion(t, db, rkvWrapper, dk.PrivateId, []byte("data-key-2"))
		assert.Equal(uint32(2), dkv2.Version)

		dk2 := testDataKey(t, db, rk.PrivateId, "test-2")
		dkv3 := testDataKeyVersion(t, db, rkvWrapper, dk2.PrivateId, []byte("data-key-1"))
		assert.Equal(uint32(1), dkv1.Version)

		found = &dataKeyVersion{
			PrivateId:       dkv3.PrivateId,
			tableNamePrefix: DefaultTableNamePrefix,
		}
		require.NoError(rw.LookupBy(testCtx, found, dbw.WithTable(found.TableName())))
		found.Decrypt(testCtx, wrapper)
		assert.Equal(dkv3, found)
	})
	t.Run("test-dup-purpose", func(t *testing.T) {
		const testPurpose = "test"
		require := require.New(t)
		db, _ := TestDb(t)
		rw := dbw.New(db)
		testScopeId := "o_1234567890"
		rk := testRootKey(t, db, testScopeId)

		// first data key with testPurpose
		_ = testDataKey(t, db, rk.PrivateId, testPurpose)

		// we can't use the std test fixture of TestDataKey(...) because
		// it's guaranteed to succeed even with duplicates
		k, err := newDataKey(rk.PrivateId, testPurpose)
		require.NoError(err)
		id, err := dbw.NewId(dataKeyPrefix)
		require.NoError(err)
		k.PrivateId = id
		k.RootKeyId = rk.PrivateId
		err = rw.Create(context.Background(), k)
		require.Error(err)
	})
}
