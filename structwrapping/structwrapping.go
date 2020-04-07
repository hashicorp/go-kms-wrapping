package structwrapping

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	wrapping "github.com/hashicorp/go-kms-wrapping"
)

type entry struct {
	index int
}

type encDecMap map[string][2]*entry

func buildEncDecMap(ctx context.Context, in interface{}) (encDecMap, error) {
	val := reflect.ValueOf(in)
	switch {
	case !val.IsValid():
		return nil, errors.New("input not valid")
	case val.IsZero():
		return nil, errors.New("input was not initialized")
	case val.Kind() != reflect.Ptr:
		return nil, errors.New("input not a pointer")
	}

	val = reflect.Indirect(val)
	if val.Kind() != reflect.Struct {
		return nil, errors.New("input not a struct")
	}

	typ := val.Type()
	// plaintext,ciphertext
	edMap := make(encDecMap, typ.NumField()/2)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag, ok := field.Tag.Lookup("wrapping")
		if !ok {
			continue
		}
		tagParts := strings.Split(tag, ",")
		if len(tagParts) != 2 {
			return nil, errors.New("error in wrapping tag specification")
		}

		fieldKind := field.Type.Kind()
		switch tagParts[0] {
		case "pt":
			if fieldKind != reflect.Slice {
				return nil, errors.New("plaintext value is not a slice")
			}
			if !field.Type.ConvertibleTo(reflect.TypeOf([]byte(nil))) {
				return nil, errors.New("plaintext value is not a byte slice")
			}
			curr := edMap[tagParts[1]]
			if curr[0] != nil {
				return nil, errors.New("detected two pt wrapping tags with the same identifier")
			}
			curr[0] = &entry{index: i}
			edMap[tagParts[1]] = curr

		case "ct":
			if fieldKind != reflect.Ptr {
				return nil, errors.New("ciphertext value is not a pointer")
			}
			if !field.Type.ConvertibleTo(reflect.TypeOf((*wrapping.EncryptedBlobInfo)(nil))) {
				return nil, errors.New("ciphertext value is not the expected type")
			}
			curr := edMap[tagParts[1]]
			if curr[1] != nil {
				return nil, errors.New("detected two ct wrapping tags with the same identifier")
			}
			curr[1] = &entry{index: i}
			edMap[tagParts[1]] = curr

		default:
			return nil, errors.New("unknown tag type for wrapping tag")
		}
	}

	for k, v := range edMap {
		if v[0] == nil {
			return nil, fmt.Errorf("no pt wrapping tag found for identifier %q", k)
		}
		if v[1] == nil {
			return nil, fmt.Errorf("no ct wrapping tag found for identifier %q", k)
		}
	}

	return edMap, nil
}

func WrapStruct(ctx context.Context, wrapper wrapping.Wrapper, in interface{}, aad []byte) error {
	if wrapper == nil {
		return errors.New("nil wrapper passed in")
	}

	edMap, err := buildEncDecMap(ctx, in)
	if err != nil {
		return err
	}

	val := reflect.Indirect(reflect.ValueOf(in))
	for _, v := range edMap {
		encRaw := val.Field(v[0].index).Interface()
		enc, ok := encRaw.([]byte)
		if !ok {
			return errors.New("could not convert value for encryption to []byte")
		}
		if enc == nil {
			return errors.New("plaintext byte slice is nil")
		}
		blobInfo, err := wrapper.Encrypt(ctx, enc, aad)
		if err != nil {
			return fmt.Errorf("error wrapping value: %w", err)
		}
		val.Field(v[1].index).Set(reflect.ValueOf(blobInfo))
	}

	return nil
}

func UnwrapStruct(ctx context.Context, wrapper wrapping.Wrapper, in interface{}, aad []byte) error {
	if wrapper == nil {
		return errors.New("nil wrapper passed in")
	}

	edMap, err := buildEncDecMap(ctx, in)
	if err != nil {
		return err
	}

	val := reflect.Indirect(reflect.ValueOf(in))
	for _, v := range edMap {
		decRaw := val.Field(v[1].index).Interface()
		dec, ok := decRaw.(*wrapping.EncryptedBlobInfo)
		if !ok {
			return errors.New("could not convert value for decryption to *wrapping.EncryptedBlobInfo")
		}
		if dec == nil {
			return errors.New("ciphertext pointer is nil")
		}
		bs, err := wrapper.Decrypt(ctx, dec, aad)
		if err != nil {
			return fmt.Errorf("error unwrapping value: %w", err)
		}
		val.Field(v[0].index).Set(reflect.ValueOf(bs))
	}

	return nil
}
