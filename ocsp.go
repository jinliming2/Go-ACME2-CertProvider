package ACME2_CertProvider

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

func getOCSPExpiredDate(OCSP *[]byte, cert, issuer *x509.Certificate) (*time.Time, error) {
	response, err := ocsp.ParseResponseForCert(*OCSP, cert, issuer)
	if err != nil {
		return nil, err
	}
	if response.Status != ocsp.Good {
		return nil, errors.New("OCSP Not Good")
	}
	if response.NextUpdate.Before(time.Now()) {
		return nil, errors.New("OCSP Expired")
	}
	return &response.NextUpdate, nil
}

func loadOCSPFile(fileName string, cert, issuer *x509.Certificate) (*[]byte, *time.Time, error) {
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, nil, err
	}
	nextUpdate, err := getOCSPExpiredDate(&file, cert, issuer)
	if err != nil {
		return nil, nil, err
	}
	return &file, nextUpdate, nil
}

func requestOCSP(fileName string, cert, issuer *x509.Certificate) (OCSP *[]byte, OCSPNotAfter *time.Time, err error) {
	for _, OCSPServer := range cert.OCSPServer {
		var OCSPRequest *[]byte
		*OCSPRequest, err = ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{
			Hash: crypto.SHA512,
		})
		if err != nil {
			continue
		}
		OCSPRequestReader := bytes.NewReader(*OCSPRequest)
		var HTTPResponse *http.Response
		HTTPResponse, err = http.Post(OCSPServer, "application/ocsp-request", OCSPRequestReader)
		if err != nil {
			continue
		}
		*OCSP, err = ioutil.ReadAll(HTTPResponse.Body)
		HTTPResponse.Body.Close()
		if err != nil {
			continue
		}
		OCSPNotAfter, err = getOCSPExpiredDate(OCSP, cert, issuer)
		if err != nil {
			continue
		}
		ioutil.WriteFile(fileName, *OCSP, 0644)
		return
	}
	OCSP, OCSPNotAfter, err = nil, nil, errors.New("Cannot get OCSP info from all of OCSP Servers")
	return
}
