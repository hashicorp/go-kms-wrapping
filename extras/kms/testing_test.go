package kms

import (
	"context"
	"testing"

	"github.com/hashicorp/go-dbw"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_stub(t *testing.T) {
	db, _ := TestDb(t)
	rw := dbw.New(db)
	rows, err := rw.Query(context.Background(), "select * from kms_root_key", nil)
	t.Log("rows: ", rows)
	require.NoError(t, err)
}

func Test_TestDeleteKeyPurpose_TestDeleteAllKeys(t *testing.T) {
	const (
		globalScope = "global"
		orgScope    = "o_1234567890"
	)
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	db, _ := TestDb(t)
	rw := dbw.New(db)
	extWrapper := wrapping.NewTestWrapper([]byte(testDefaultWrapperSecret))

	databaseKeyPurpose := KeyPurpose("database")

	// init kms with a cache
	kmsCache, err := New(rw, rw, []KeyPurpose{"database"})
	require.NoError(err)
	require.NoError(kmsCache.AddExternalWrapper(ctx, KeyPurposeRootKey, extWrapper))
	// Make the global scope base keys
	err = kmsCache.CreateKeys(ctx, globalScope, []KeyPurpose{databaseKeyPurpose})
	require.NoError(err)

	_, err = kmsCache.GetWrapper(ctx, globalScope, databaseKeyPurpose)
	require.NoError(err)

	TestDeleteKeyPurpose(t, db, databaseKeyPurpose)

	_, err = kmsCache.GetWrapper(ctx, globalScope, databaseKeyPurpose)
	require.Error(err)
	assert.ErrorIs(err, ErrKeyNotFound)

	err = kmsCache.ReconcileKeys(ctx, []string{globalScope}, []KeyPurpose{databaseKeyPurpose})
	require.NoError(err)

	_, err = kmsCache.GetWrapper(ctx, globalScope, databaseKeyPurpose)
	require.NoError(err)

	err = kmsCache.CreateKeys(ctx, orgScope, []KeyPurpose{databaseKeyPurpose})
	require.NoError(err)

	TestKmsDeleteAllKeys(t, db)

	_, err = kmsCache.GetWrapper(ctx, globalScope, databaseKeyPurpose)
	require.Error(err)
	assert.ErrorIs(err, ErrKeyNotFound)

	_, err = kmsCache.GetWrapper(ctx, orgScope, databaseKeyPurpose)
	require.Error(err)
	assert.ErrorIs(err, ErrKeyNotFound)

	_, err = kmsCache.GetWrapper(ctx, globalScope, KeyPurposeRootKey)
	require.Error(err)
	assert.ErrorIs(err, ErrKeyNotFound)
}
