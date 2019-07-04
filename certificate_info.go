package ACME2_CertProvider

import (
	"crypto/tls"
	"crypto/x509"
	"time"
)

type certificateInfo struct {
	Certificate  *tls.Certificate
	NotAfter     *time.Time
	x509Cert     *x509.Certificate
	x509Issuer   *x509.Certificate
	OCSPFileName string
	OCSPNotAfter *time.Time
}
