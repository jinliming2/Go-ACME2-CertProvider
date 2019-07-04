package ACME2_CertProvider

import (
	"fmt"
	"time"
)

// AcmeServerDirectory ...
type AcmeServerDirectory string

const (
	// LetsEncryptStaging ...
	LetsEncryptStaging AcmeServerDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"
	// LetsEncryptProduction ...
	LetsEncryptProduction AcmeServerDirectory = "https://acme-v02.api.letsencrypt.org/directory"
)

type directoryContextType string

const (
	ctxDirectory directoryContextType = "directory"
	ctxKey       directoryContextType = "key"
	ctxKid       directoryContextType = "kid"
	ctxOrder     directoryContextType = "order"
	ctxCSR       directoryContextType = "csr"
)

type acmeError struct {
	Type     string `json:"type"`
	Title    string `json:"title,omitempty"`
	Status   int    `json:"status,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

func (err *acmeError) Error() string {
	return fmt.Sprintf("%d %s(%s): %s", err.Status, err.Title, err.Type, err.Detail)
}

type jws struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type directory struct {
	Meta struct {
		TermsOfService string `json:"termsOfService"`
	} `json:"meta"`
	NewAccount string `json:"newAccount"`
	NewNonce   string `json:"newNonce"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
}

type accountInfo struct {
	Contact              []string `json:"contact"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
}

type acmeAccount struct {
	ID        int         `json:"id"`
	Key       interface{} `json:"key"`
	Contact   []string    `json:"contact"`
	InitialIP string      `json:"initialIp"`
	CreatedAt string      `json:"createdAt"`
	Status    string      `json:"status"`
}

type certificateIdentifiers struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type orderRequest struct {
	Identifiers []certificateIdentifiers `json:"identifiers"`
}

type orderStatus string

const (
	orderPending    orderStatus = "pending"
	orderReady      orderStatus = "ready"
	orderProcessing orderStatus = "processing"
	orderValid      orderStatus = "valid"
	orderInvalid    orderStatus = "invalid"
)

type acmeOrder struct {
	Status         orderStatus              `json:"status"`
	Expires        *time.Time               `json:"expires,omitempty"`
	Identifiers    []certificateIdentifiers `json:"identifiers"`
	Authorizations []string                 `json:"authorizations"`
	Finalize       string                   `json:"finalize"`
	Certificate    string                   `json:"certificate,omitempty"`
}

type authorizationStatus string

const (
	authorizationPending     authorizationStatus = "pending"
	authorizationValid       authorizationStatus = "valid"
	authorizationInvalid     authorizationStatus = "invalid"
	authorizationDeactivated authorizationStatus = "deactivated"
	authorizationExpired     authorizationStatus = "expired"
	authorizationRevoked     authorizationStatus = "revoked"
)

type challenge struct {
	Type   string              `json:"type"`
	URL    string              `json:"url"`
	Status authorizationStatus `json:"status"`
	Token  string              `json:"token"`
}

type acmeAuthorization struct {
	Identifier certificateIdentifiers `json:"identifier"`
	Status     authorizationStatus    `json:"status"`
	Expires    *time.Time             `json:"expires,omitempty"`
	Challenges []challenge            `json:"challenges"`
	Wildcard   bool                   `json:"wildcard,omitempty"`
}

type acmeCSRRequest struct {
	CSR string `json:"csr"`
}
