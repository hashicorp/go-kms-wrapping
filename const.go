package wrapping

type WrapperType uint32

// These values define known types of Wrappers
const (
	WrapperTypeUnknown WrapperType = iota
	WrapperTypeAead
	WrapperTypeAliCloudKms
	WrapperTypeAwsKms
	WrapperTypeAzureKeyVault
	WrapperTypeGcpCkms
	WrapperTypeHsmAuto
	WrapperTypeHuaweiCloudKms
	WrapperTypeMultiWrapper
	WrapperTypeOciKms
	WrapperTypePkcs11
	WrapperTypeShamir
	WrapperTypeTencentCloudKms
	WrapperTypeTransit
	WrapperTypeYandexCloudKms
	WrapperTypeTest
)

func (t WrapperType) String() string {
	switch t {
	case WrapperTypeAead:
		return "aead"
	case WrapperTypeAliCloudKms:
		return "alicloudkms"
	case WrapperTypeAwsKms:
		return "awskms"
	case WrapperTypeAzureKeyVault:
		return "azurekeyvault"
	case WrapperTypeGcpCkms:
		return "gcpckms"
	case WrapperTypeHsmAuto:
		return "hsm-auto"
	case WrapperTypeHuaweiCloudKms:
		return "huaweicloudkms"
	case WrapperTypeMultiWrapper:
		return "multiwrapper"
	case WrapperTypeOciKms:
		return "ocikms"
	case WrapperTypePkcs11:
		return "pkcs11"
	case WrapperTypeShamir:
		return "shamir"
	case WrapperTypeTencentCloudKms:
		return "tencentcloudkms"
	case WrapperTypeTransit:
		return "transit"
	case WrapperTypeYandexCloudKms:
		return "yandexcloudkms"
	case WrapperTypeTest:
		return "test-auto"
	default:
		return "unknown"
	}
}

type AeadType uint

// These values define supported types of AEADs
const (
	AeadTypeUnknown AeadType = iota
	AeadTypeAesGcm
)

func (t AeadType) String() string {
	switch t {
	case AeadTypeAesGcm:
		return "aes-gcm"
	default:
		return "unknown"
	}
}
