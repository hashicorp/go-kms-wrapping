package kms_test

import (
	"context"
	"testing"

	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-kms-wrapping/extras/kms/v2"

	"github.com/stretchr/testify/require"
)

func Test_stub(t *testing.T) {
	db, _ := kms.TestDb(t)
	rw := dbw.New(db)
	rows, err := rw.Query(context.Background(), "select * from kms_root_key", nil)
	t.Log("rows: ", rows)
	require.NoError(t, err)
}
