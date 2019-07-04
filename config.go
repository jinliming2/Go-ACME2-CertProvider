package ACME2_CertProvider

import (
	"time"
)

// Config describes how CertificateProvider works
type Config struct {
	DomainList         []string
	CertificateSaveDir string
	CSRFilePath        string
	WebsiteKeyPath     string
	AccountKeyPath     string
	AccountKeyPassword []byte

	// AgreeTermsOfService must be true if you agree to the terms of service from the ACME server.
	// Otherwise, ACME client doesn't work, and you cannot issue certificate automated.
	//
	// The document of terms of service from the ACME server will be stored in CertificateSaveDir.
	AgreeTermsOfService bool

	ACMEDirectory AcmeServerDirectory
	ContactEmail  []string
	Method        challengeMethod
	RenewDays     time.Duration
}
