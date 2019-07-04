package ACME2_CertProvider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"strings"
	"time"
)

func loadExistsCertificateFromDirectory(dir, keyPath string, info *certificateInfo) (*tls.Certificate, error) {
	fileInfo, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var fileName string
	maxTime := time.Time{}
	for _, info := range fileInfo {
		if info.IsDir() {
			continue
		}
		name := info.Name()
		time, err := time.Parse("2006-01-02.crt", name)
		if err != nil {
			continue
		}
		if time.After(maxTime) {
			maxTime = time
			fileName = dir + "/" + name
		}
	}
	if fileName == "" {
		return nil, errors.New("No Certificate found")
	}
	return loadExistsCertificateFromDirectory(dir, keyPath, info)
}

func loadCertificateFromFile(fileName, keyPath string, info *certificateInfo) (cert *tls.Certificate, err error) {
	// Load Certificate
	*cert, err = tls.LoadX509KeyPair(fileName, keyPath)
	if err != nil {
		return nil, err
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	// Check if certificate was not expired
	if time.Now().After(x509Cert.NotAfter) {
		return nil, errors.New("Certificate expired")
	}
	info.Certificate = cert
	info.NotAfter = &x509Cert.NotAfter
	info.x509Cert = x509Cert
	// Check if certificate can verified by OCSP
	if len(cert.Certificate) > 1 {
		if x509Issuer, OCSPErr := x509.ParseCertificate(cert.Certificate[1]); OCSPErr == nil {
			info.x509Issuer = x509Issuer
			info.OCSPFileName = fileName + ".ocsp"
			// Load OCSP info from exists file
			if OCSP, OCSPNotAfter, OCSPErr := loadOCSPFile(info.OCSPFileName, x509Cert, x509Issuer); OCSPErr == nil {
				if OCSPNotAfter != nil && time.Now().Before(*OCSPNotAfter) {
					info.Certificate.OCSPStaple = *OCSP
					info.OCSPNotAfter = OCSPNotAfter
				}
			}
		}
	}
	return
}

func loadPrivateKey(PEMBlock []byte, password []byte) (crypto.PrivateKey, error) {
	var DERBlock *pem.Block
	for {
		DERBlock, PEMBlock = pem.Decode(PEMBlock)
		if DERBlock == nil {
			return nil, errors.New("No private key found")
		}
		if DERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(DERBlock.Type, " PRIVATE KEY") {
			break
		}
	}

	block := DERBlock.Bytes
	if x509.IsEncryptedPEMBlock(DERBlock) {
		var err error
		block, err = x509.DecryptPEMBlock(DERBlock, password)
		if err != nil {
			return nil, err
		}
	}

	if key, err := x509.ParsePKCS1PrivateKey(block); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("Found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(block); err == nil {
		return key, nil
	}

	return nil, errors.New("Failed to parse private key")
}

func issueNewCertificate(config *Config, dir string, info *certificateInfo) (*tls.Certificate, error) {
	ctx := context.Background()
	var certData *[]byte
	var err error
	// Issue Certificate
	switch config.Method {
	case HTTP01:
		certData, err = issueCertificateByHTTP01(ctx, config)
	case DNS01:
		certData, err = issueCertificateByDNS01(ctx, config)
	case TLSSNI01:
		certData, err = issueCertificateByTLSSNI01(ctx, config)
	case TLSALPN01:
		certData, err = issueCertificateByTLSALPN01(ctx, config)
	default:
		return nil, errors.New("Unknown Issue Method")
	}
	if err != nil {
		return nil, err
	}
	fileName := dir + "/" + time.Now().Format("2006-01-02.crt")
	err = ioutil.WriteFile(fileName, *certData, 0644)
	if err != nil {
		return nil, err
	}
	return loadCertificateFromFile(fileName, config.WebsiteKeyPath, info)
}
