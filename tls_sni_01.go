package ACME2_CertProvider

import (
	"context"
	"errors"
)

func issueCertificateByTLSSNI01(ctx context.Context, config *Config) (*[]byte, error) {
	return nil, errors.New("Not Implemented: TLS-SNI-01 was deprecated")
}
