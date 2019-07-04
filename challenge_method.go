package ACME2_CertProvider

// challengeMethod enumerates the different method to validate the right of control from you
type challengeMethod int

const (
	// HTTP01 HTTP-01 Challenge
	//
	// https://letsencrypt.org/docs/challenge-types/#http-01-challenge
	// The HTTP-01 challenge can only be done on port 80,
	// and Let’s Encrypt doesn’t let you use this challenge to issue wildcard certificates.
	HTTP01 challengeMethod = iota

	// DNS01 DNS-01 Challenge
	//
	// https://letsencrypt.org/docs/challenge-types/#dns-01-challenge
	// You can use this challenge to issue certificates containing wildcard domain names.
	DNS01

	// TLSSNI01 TLS-SNI-01 Challenge
	//
	// https://letsencrypt.org/docs/challenge-types/#tls-sni-01
	// Deprecated: It was disabled in March 2019 because it was not secure enough.
	TLSSNI01

	// TLSALPN01 TLS-ALPN-01 Challenge
	//
	// https://letsencrypt.org/docs/challenge-types/#tls-alpn-01
	TLSALPN01
)
