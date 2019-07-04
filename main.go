package ACME2_CertProvider

import (
	"crypto/tls"
	"errors"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

type configCertificatePair struct {
	*Config
	certificate func() (*tls.Certificate, error)
}

var certificateList []configCertificatePair

// DefaultDomain used for that client doesn't support SNI
const DefaultDomain = "@@DEFAULT_DOMAIN@@"

// GetCertificate ...
func GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var serverName string
	if info.ServerName != "" {
		serverName = info.ServerName
	} else {
		serverName = DefaultDomain
	}
	return SearchCertificate(serverName)
}

// SearchCertificate ...
func SearchCertificate(serverName string) (*tls.Certificate, error) {
	for _, certificate := range certificateList {
	domainLoop:
		for _, domain := range certificate.DomainList {
			if strings.Contains(domain, "*") {
				_domain := strings.Split(domain, ".")
				_serverName := strings.Split(serverName, ".")
				if len(_domain) != len(_serverName) {
					continue
				}
				for i, part := range _domain {
					if i == 0 && part == "*" {
						continue
					}
					if _serverName[i] != part {
						continue domainLoop
					}
				}
				return certificate.certificate()
			}
			if domain == serverName {
				return certificate.certificate()
			}
		}
	}
	return nil, errors.New("No such domain: " + serverName)
}

type certificateAndError struct {
	certificate *tls.Certificate
	err         error
}

// CreateCertificate ...
func CreateCertificate(config *Config) func() (*tls.Certificate, error) {
	var info certificateInfo
	certificate := func() (cert *tls.Certificate, err error) {
		defer func() {
			if cert == nil || info.OCSPFileName == "" {
				return
			}

			// Check if OCSP info not expired
			if time.Now().Before(*info.OCSPNotAfter) {
				return
			}

			// Refresh OCSP info
			if OCSP, OCSPNotAfter, err := requestOCSP(info.OCSPFileName, info.x509Cert, info.x509Issuer); err == nil {
				info.Certificate.OCSPStaple = *OCSP
				info.OCSPNotAfter = OCSPNotAfter
			}
		}()

		certChain := make(chan *certificateAndError)

		// Check if Certificate not expired
		if info.NotAfter != nil && time.Now().Before(*info.NotAfter) {
			if info.NotAfter.Sub(time.Now()) > config.RenewDays {
				// No need to renew
				cert = info.Certificate
				return
			}
			certChain <- &certificateAndError{info.Certificate, nil}
			// Time to renew certificate...
		}

		go func() {
			// Load or Renew
			dir := strings.TrimSuffix(config.CertificateSaveDir, "/")

			// File Lock
			fileLock := flock.New(dir + "/cert.lock")
			defer fileLock.Unlock()
			if info.NotAfter == nil {
				// Load. Must Lock
				err = fileLock.Lock()
				if err != nil {
					certChain <- &certificateAndError{nil, err}
					return
				}
			} else {
				// Renew. If Locking, may issuing
				ok, err := fileLock.TryLock()
				if err != nil || !ok {
					return
				}
			}

			// Never load certificate before
			if info.NotAfter == nil {
				// Load Exists Certificate
				if cert, err = loadExistsCertificateFromDirectory(dir, config.WebsiteKeyPath, &info); err == nil {
					certChain <- &certificateAndError{cert, err}
					if info.NotAfter.Sub(time.Now()) > config.RenewDays {
						return
					}
					// Time to renew certificate...
				}
			}

			// Issue new certificate
			cert, err = issueNewCertificate(config, dir, &info)
			certChain <- &certificateAndError{cert, err}
		}()

		c := <-certChain
		cert, err = c.certificate, c.err
		return
	}
	certificateList = append(certificateList, configCertificatePair{
		Config:      config,
		certificate: certificate,
	})
	return certificate
}
