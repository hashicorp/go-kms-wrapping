package structwrapping

import (
	"context"
	"errors"
	"reflect"
	"strings"

	wrapping "github.com/hashicorp/go-kms-wrapping"
)

func WrapStruct(ctx context.Context, in interface{}) error {
	val := reflect.ValueOf(in)
	switch {
	case !val.IsValid():
		return errors.New("input not valid")
	case val.IsZero():
		return errors.New("input was not initialized")
	case val.Kind() != reflect.Ptr:
		return errors.New("input not a pointer")
	}

	val = reflect.Indirect(val)
	if val.Kind() != reflect.Struct {
		return errors.New("input not a struct")
	}

	type entry struct {
		index int
	}

	typ := val.Type()
	// plaintext,ciphertext
	encDecMap := make(map[string][2]entry, len(typ.NumField()/2))
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag, ok := field.Tag.Lookup("wrapping")
		if !ok {
			continue
		}
		tagParts := strings.Split(tag, ",")
		if len(tagParts) != 2 {
			return errors.New("error in wrapping tag specification")
		}

		fieldKind := field.Type.Kind()
		switch tagParts[0] {
		case "pt":
			if fieldKind != reflect.Slice {
				return errors.New("plaintext value is not a slice")
			}
			if !field.Type.ConvertibleTo(reflect.TypeOf([]byte(nil))) {
				return errors.New("plaintext value is not a byte slice")
			}
			curr := encDecMap[tag]
			curr[0] = entry{index: i, field: field}
			encDecMap[tag] = curr

		case "ct":
			if fieldKind != reflect.Ptr {
				return errors.New("ciphertext value is not a pointer")
			}
			if !field.Type.ConvertibleTo(reflect.TypeOf((*wrapping.EncryptedBlobInfo)(nil))) {
				return errors.New("ciphertext value is not the expected type")
			}
			curr := encDecMap[tag]
			curr[1] = entry{index: i, field: field}
			encDecMap[tag] = curr

		default:
			return errors.New("unknown tag type for wrapping tag")
		}
	}

	return nil
}
