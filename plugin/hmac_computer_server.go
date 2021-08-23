package plugin

import (
	context "context"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

type hmacComputerServer struct {
	UnimplementedHmacComputerServer
	impl wrapping.HmacComputer
}

func (hcs *hmacComputerServer) HmacKeyId(ctx context.Context, req *HmacKeyIdRequest) (*HmacKeyIdResponse, error) {
	hmacKeyId, err := hcs.impl.HmacKeyId(ctx)
	if err != nil {
		return nil, err
	}
	return &HmacKeyIdResponse{KeyId: hmacKeyId}, nil
}
