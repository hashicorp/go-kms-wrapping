package kms_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootKeyVersion_ImmutableFields(t *testing.T) {
	t.Parallel()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(kms.DefaultWrapperSecret))

	testScopeId := "o_1234567890"
	rk := kms.TestRootKey(t, db, testScopeId)
	new, _ := kms.TestRootKeyVersion(t, db, wrapper, rk.PrivateId)

	tests := []struct {
		name      string
		update    *kms.RootKeyVersion
		fieldMask []string
	}{
		{
			name:      "private_id",
			update:    new.Clone(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create_time",
			update: func() *kms.RootKeyVersion {
				k := new.Clone()
				k.CreateTime = time.Now()
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "root_key_id",
			update: func() *kms.RootKeyVersion {
				k := new.Clone()
				k.RootKeyId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "version",
			update: func() *kms.RootKeyVersion {
				k := new.Clone()
				k.Version = uint32(22)
				return k
			}(),
			fieldMask: []string{"Version"},
		},
		{
			name: "key",
			update: func() *kms.RootKeyVersion {
				k := new.Clone()
				k.Key = []byte("updated key")
				return k
			}(),
			fieldMask: []string{"CtKey"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.Clone()
			err := rw.LookupBy(context.Background(), orig)
			require.NoError(err)

			err = tc.update.Encrypt(context.Background(), wrapper)
			require.NoError(err)
			rowsUpdated, err := rw.Update(context.Background(), tc.update, tc.fieldMask, nil)
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupBy(context.Background(), after)
			require.NoError(err)

			assert.Equal(orig, after)
		})
	}
}

func TestRootKey_ImmutableFields(t *testing.T) {
	t.Parallel()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)

	testScopeId := "o_1234567890"
	new := kms.TestRootKey(t, db, testScopeId)

	tests := []struct {
		name      string
		update    *kms.RootKey
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.RootKey {
				k := new.Clone()
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create_time",
			update: func() *kms.RootKey {
				k := new.Clone()
				k.CreateTime = time.Now()
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "scope_id",
			update: func() *kms.RootKey {
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
			err := rw.LookupBy(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := rw.Update(context.Background(), tc.update, tc.fieldMask, nil)
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupBy(context.Background(), after)
			require.NoError(err)

			assert.Equal(orig, after)
		})
	}
}

func TestDataKey_ImmutableFields(t *testing.T) {
	t.Parallel()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)

	testScopeId := "o_1234567890"
	rk := kms.TestRootKey(t, db, testScopeId)
	new := kms.TestDataKey(t, db, rk.PrivateId, "test")

	tests := []struct {
		name      string
		update    *kms.DataKey
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.DataKey {
				k := new.Clone()
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create_time",
			update: func() *kms.DataKey {
				k := new.Clone()
				k.CreateTime = time.Now()
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "root_key_id",
			update: func() *kms.DataKey {
				k := new.Clone()
				k.RootKeyId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "purpose",
			update: func() *kms.DataKey {
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
			orig := new.Clone()
			err := rw.LookupBy(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := rw.Update(context.Background(), tc.update, tc.fieldMask, nil)
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupBy(context.Background(), after)
			require.NoError(err)

			assert.Equal(orig, after)
		})
	}
}

func TestDataKeyVersion_ImmutableFields(t *testing.T) {
	t.Parallel()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(kms.DefaultWrapperSecret))

	testScopeId := "o_1234567890"
	rk := kms.TestRootKey(t, db, testScopeId)
	_, rkvWrapper := kms.TestRootKeyVersion(t, db, wrapper, rk.PrivateId)

	dk := kms.TestDataKey(t, db, rk.PrivateId, "test")
	new := kms.TestDataKeyVersion(t, db, rkvWrapper, dk.PrivateId, []byte("data-key"))

	tests := []struct {
		name      string
		update    *kms.DataKeyVersion
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *kms.DataKeyVersion {
				k := new.Clone()
				k.PrivateId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create_time",
			update: func() *kms.DataKeyVersion {
				k := new.Clone()
				k.CreateTime = time.Now()
				return k
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "data_key_id",
			update: func() *kms.DataKeyVersion {
				k := new.Clone()
				k.DataKeyId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "root_key_version_id",
			update: func() *kms.DataKeyVersion {
				k := new.Clone()
				k.RootKeyVersionId = "o_thisIsNotAValidId"
				return k
			}(),
			fieldMask: []string{"RootKeyId"},
		},
		{
			name: "version",
			update: func() *kms.DataKeyVersion {
				k := new.Clone()
				k.Version = uint32(22)
				return k
			}(),
			fieldMask: []string{"Version"},
		},
		{
			name: "key",
			update: func() *kms.DataKeyVersion {
				k := new.Clone()
				k.Key = []byte("updated key")
				return k
			}(),
			fieldMask: []string{"CtKey"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.Clone()
			err := rw.LookupBy(context.Background(), orig)
			require.NoError(err)

			err = tc.update.Encrypt(context.Background(), wrapper)
			require.NoError(err)
			rowsUpdated, err := rw.Update(context.Background(), tc.update, tc.fieldMask, nil)
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = rw.LookupBy(context.Background(), after)
			require.NoError(err)

			assert.Equal(orig, after)
		})
	}
}

func TestRootKey_Version(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	testCtx := context.Background()
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	wrapper := wrapping.NewTestWrapper([]byte(kms.DefaultWrapperSecret))

	testScopeId := "o_1234567890"
	rk := kms.TestRootKey(t, db, testScopeId)
	rkv1, _ := kms.TestRootKeyVersion(t, db, wrapper, rk.PrivateId)
	assert.Equal(uint32(1), rkv1.Version)

	found := &kms.RootKeyVersion{
		PrivateId: rkv1.PrivateId,
	}
	require.NoError(rw.LookupBy(testCtx, found))
	found.Decrypt(testCtx, wrapper)
	assert.Equal(rkv1, found)

	rkv2, _ := kms.TestRootKeyVersion(t, db, wrapper, rk.PrivateId)
	assert.Equal(uint32(2), rkv2.Version)
}

func TestDataKey_Version(t *testing.T) {
	t.Run("test-version-trigger", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		testCtx := context.Background()
		db, _ := kms.TestDb(t)
		rw := dbw.New(db)
		wrapper := wrapping.NewTestWrapper([]byte(kms.DefaultWrapperSecret))

		testScopeId := "o_1234567890"
		rk := kms.TestRootKey(t, db, testScopeId)
		_, rkvWrapper := kms.TestRootKeyVersion(t, db, wrapper, rk.PrivateId)

		dk := kms.TestDataKey(t, db, rk.PrivateId, "test")

		dkv1 := kms.TestDataKeyVersion(t, db, rkvWrapper, dk.PrivateId, []byte("data-key-1"))
		assert.Equal(uint32(1), dkv1.Version)

		found := &kms.DataKeyVersion{
			PrivateId: dkv1.PrivateId,
		}
		require.NoError(rw.LookupBy(testCtx, found))
		found.Decrypt(testCtx, wrapper)
		assert.Equal(dkv1, found)

		dkv2 := kms.TestDataKeyVersion(t, db, rkvWrapper, dk.PrivateId, []byte("data-key-2"))
		assert.Equal(uint32(2), dkv2.Version)

		dk2 := kms.TestDataKey(t, db, rk.PrivateId, "test-2")
		dkv3 := kms.TestDataKeyVersion(t, db, rkvWrapper, dk2.PrivateId, []byte("data-key-1"))
		assert.Equal(uint32(1), dkv1.Version)

		found = &kms.DataKeyVersion{
			PrivateId: dkv3.PrivateId,
		}
		require.NoError(rw.LookupBy(testCtx, found))
		found.Decrypt(testCtx, wrapper)
		assert.Equal(dkv3, found)

	})
	t.Run("test-dup-purpose", func(t *testing.T) {
		const testPurpose = "test"
		require := require.New(t)
		db, _ := kms.TestDb(t)
		rw := dbw.New(db)
		testScopeId := "o_1234567890"
		rk := kms.TestRootKey(t, db, testScopeId)

		// first data key with testPurpose
		_ = kms.TestDataKey(t, db, rk.PrivateId, testPurpose)

		// we can't use the std test fixture of kms.TestDataKey(...) because
		// it's guaranteed to succeed even with duplicates
		k, err := kms.NewDataKey(rk.PrivateId, testPurpose)
		require.NoError(err)
		id, err := dbw.NewId(kms.DataKeyPrefix)
		require.NoError(err)
		k.PrivateId = id
		k.RootKeyId = rk.PrivateId
		err = rw.Create(context.Background(), k)
		require.Error(err)
	})
}
