package ACME2_CertProvider

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

func issueCertificateByDNS01(ctx context.Context, config *Config) (*[]byte, error) {
	ctx, err := acmeIssueReady(ctx, config)
	if err != nil {
		return nil, err
	}

	dir := ctx.Value(ctxDirectory).(*directory)
	// Create Certificate Order
	request := orderRequest{
		Identifiers: make([]certificateIdentifiers, len(config.DomainList)),
	}
	for i, domain := range config.DomainList {
		request.Identifiers[i] = certificateIdentifiers{Type: "dns", Value: domain}
	}
	order := acmeOrder{}
	orderLink, err := post(ctx, dir.NewOrder, request, wantsStatus(201), &order)
	if err != nil {
		return nil, err
	}
	if orderLink == "" {
		return nil, errors.New("Cannot create Order")
	}
	if order.Status != orderPending {
		return nil, errors.New("Invalid order status: " + string(order.Status))
	}
	ctx = context.WithValue(ctx, ctxOrder, &orderLink)

	// Order Authorization
	authChain := make([]chan bool, len(order.Authorizations))
	cancelChain := make([]context.CancelFunc, len(order.Authorizations))
	for i, auth := range order.Authorizations {
		var authCtx context.Context
		authCtx, cancelChain[i] = context.WithCancel(ctx)
		go issueAuthorizationByDNS01(authCtx, auth, authChain[i])
	}
	for i, auth := range authChain {
		authResult := <-auth
		if !authResult {
			// Authorization Failed
			for _, cancel := range cancelChain {
				// Cancel All Authorization Process
				cancel()
			}
			return nil, errors.New("Authorization Failed: " + order.Authorizations[i])
		}
	}
	for _, cancel := range cancelChain {
		cancel()
	}
	// Finish and Download
	return acmeIssueFinalize(ctx)
}

type dnsQueryAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type dnsQueryResult struct {
	Status int              `json:"Status"`
	Answer []dnsQueryAnswer `json:"Answer"`
}

func issueAuthorizationByDNS01(ctx context.Context, auth string, result chan<- bool) {
	// Get Auth Info
	info := acmeAuthorization{}
	_, err := get(ctx, auth, wantsStatus(200), &info)
	if err != nil {
		result <- false
		return
	}
	if info.Status == authorizationValid {
		result <- true
		return
	}
	if info.Status != authorizationPending {
		result <- false
		return
	}
	if len(info.Challenges) < 1 {
		result <- false
		return
	}
	c := info.Challenges[0]
	if c.Status == authorizationValid {
		result <- true
		return
	}
	token, err := generateDNS01Token(ctx, c.Token)
	if err != nil {
		result <- false
		return
	}

	DNSChallengeDomain := "_acme-challenge." + strings.TrimPrefix(info.Identifier.Value, "*.")
	// TODO: Put TOKEN on DNS Server
	println(token)

	// Check TOKEN valid
	_, err = getDNS(ctx, DNSChallengeDomain, "TXT", func(result *dnsQueryResult) bool {
		for _, answer := range result.Answer {
			if answer.Data == "\""+token+"\"" || answer.Data == token {
				return true
			}
		}
		return false
	})
	// Check Authorization
	_, err = post(ctx, c.URL, map[string]string{}, wantsStatus(200), &c)
	if err != nil {
		result <- false
		return
	}
	for {
		if c.Status == authorizationValid {
			result <- true
			return
		}
		if c.Status != authorizationPending {
			result <- false
			return
		}
		time.Sleep(time.Second)
		_, err = get(ctx, c.URL, wantsStatus(200), &c)
	}
}

func generateDNS01Token(ctx context.Context, token string) (string, error) {
	privateKey := ctx.Value(ctxKey).(*crypto.Signer)
	finger, err := jwkThumbprint((*privateKey).Public())
	if err != nil {
		return "", err
	}
	keyAuthShaBytes := sha256.Sum256([]byte(token + "." + finger))
	return base64.RawURLEncoding.EncodeToString(keyAuthShaBytes[:sha256.Size]), nil
}
