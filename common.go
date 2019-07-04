package ACME2_CertProvider

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	minWait = 100 * time.Millisecond
	maxWait = 10 * time.Second
)

type statusOkay func(*http.Response) bool

func wantsStatus(status ...int) statusOkay {
	return func(response *http.Response) bool {
		for _, code := range status {
			if code == response.StatusCode {
				return true
			}
		}
		return false
	}
}

func retryAfter(v string) time.Duration {
	if i, err := strconv.Atoi(v); err == nil {
		return time.Duration(i) * time.Second
	}
	t, err := http.ParseTime(v)
	if err != nil {
		return 0
	}
	return t.Sub(time.Now())
}

func waitForRetry(ctx context.Context, times int, response *http.Response) error {
	var wait time.Duration
	if v := response.Header.Get("Retry-After"); v != "" {
		wait = retryAfter(v)
		if wait < minWait {
			wait = minWait
		}
	} else {
		if times < 1 {
			times = 1
		}
		if times > 30 {
			times = 30
		}
		wait = time.Duration(1<<uint(times-1)) * time.Second
		if wait > maxWait {
			wait = maxWait
		}
	}
	wakeup := time.NewTimer(wait)
	defer wakeup.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-wakeup.C:
		return nil
	}
}

func waitForTTL(ctx context.Context, TTL time.Duration) error {
	wakeup := time.NewTimer(TTL)
	defer wakeup.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-wakeup.C:
		return nil
	}
}

func responseError(response *http.Response) error {
	body, _ := ioutil.ReadAll(response.Body)
	e := acmeError{Status: response.StatusCode}
	if err := json.Unmarshal(body, &e); err != nil {
		e.Detail = string(body)
		if e.Detail == "" {
			e.Detail = response.Status
		}
	}
	return &e
}

func get(ctx context.Context, url string, ok statusOkay, result interface{}) (string, error) {
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	request = request.WithContext(ctx)
	for n := 0; ; n++ {
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			default:
				return "", err
			}
		}
		if ok(response) {
			defer response.Body.Close()
			location := response.Header.Get("Location")
			if result != nil {
				return location, json.NewDecoder(response.Body).Decode(result)
			}
			return location, nil
		}
		err = responseError(response)
		response.Body.Close()
		if response.StatusCode/100 == 4 && response.StatusCode != http.StatusTooManyRequests {
			return "", err
		}
		if waitForRetry(ctx, n, response) != nil {
			return "", err
		}
	}
}

func post(ctx context.Context, url string, body interface{}, ok statusOkay, result interface{}) (string, error) {
	kid, _ := ctx.Value(ctxKid).(*string)
	for n := 0; ; n++ {
		nonce, err := getNonce(ctx)
		if err != nil {
			return "", err
		}
		jws, err := jwsEncodeJSON(*ctx.Value(ctxKey).(*crypto.Signer), url, *kid, nonce, body)
		if err != nil {
			return "", err
		}
		request, err := http.NewRequest("POST", url, bytes.NewReader(jws))
		if err != nil {
			return "", err
		}
		request.Header.Set("Content-Type", "application/jose+json")
		request = request.WithContext(ctx)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			default:
				return "", err
			}
		}
		if ok(response) {
			addNonce(response.Header)
			defer response.Body.Close()
			location := response.Header.Get("Location")
			if result != nil {
				return location, json.NewDecoder(response.Body).Decode(result)
			}
			return location, nil
		}
		err = responseError(response)
		response.Body.Close()
		if err != nil && strings.HasSuffix(strings.ToLower(err.(*acmeError).Type), ":badnonce") {
			clearNonce()
			addNonce(response.Header)
			continue
		}
		addNonce(response.Header)
		if response.StatusCode/100 == 4 && response.StatusCode != http.StatusTooManyRequests {
			return "", err
		}
		if waitForRetry(ctx, n, response) != nil {
			return "", err
		}
	}
}

func acmeIssueReady(ctx context.Context, config *Config) (context.Context, error) {
	// Load Private Key
	accountKey, err := ioutil.ReadFile(config.AccountKeyPath)
	if err != nil {
		return ctx, err
	}
	privateKey, err := loadPrivateKey(accountKey, config.AccountKeyPassword)
	if err != nil {
		return ctx, err
	}
	ctx = context.WithValue(ctx, ctxKey, &privateKey)
	// Load CSR
	csr, err := ioutil.ReadFile(config.CSRFilePath)
	if err != nil {
		return ctx, err
	}
	csrString := base64.RawURLEncoding.EncodeToString(csr)
	ctx = context.WithValue(ctx, ctxCSR, &csrString)
	// Get Directory
	dir := directory{}
	_, err = get(ctx, string(config.ACMEDirectory), wantsStatus(200), &dir)
	if err != nil {
		return ctx, err
	}
	ctx = context.WithValue(ctx, ctxDirectory, &dir)
	// Get or Create Account
	contact := make([]string, len(config.ContactEmail))
	for i, v := range config.ContactEmail {
		contact[i] = "mailto:" + v
	}
	info := accountInfo{
		Contact:              contact,
		TermsOfServiceAgreed: config.AgreeTermsOfService,
	}
	account := acmeAccount{}
	kid, err := post(ctx, dir.NewAccount, info, wantsStatus(200, 201), &account)
	if err != nil {
		return ctx, err
	}
	if kid == "" {
		return ctx, errors.New("Cannot get account kid")
	}
	if account.Status != "valid" {
		return ctx, errors.New("Invalid account status: " + account.Status)
	}
	ctx = context.WithValue(ctx, ctxKid, &kid)
	return ctx, nil
}

func acmeIssueFinalize(ctx context.Context) (*[]byte, error) {
	order := acmeOrder{}
	// Wait For Order Ready
	for {
		_, err := get(ctx, *ctx.Value(ctxOrder).(*string), wantsStatus(200), &order)
		if err != nil {
			return nil, err
		}
		if order.Status == orderReady {
			break
		}
		if order.Status == orderInvalid {
			return nil, errors.New("Order issue failed: order invalid")
		}
		time.Sleep(time.Second)
	}
	_, err := post(ctx, order.Finalize, acmeCSRRequest{CSR: *ctx.Value(ctxCSR).(*string)}, wantsStatus(200), &order)
	if err != nil {
		return nil, err
	}
	if order.Certificate == "" {
		return nil, errors.New("Certificate field not found")
	}
	request, err := http.NewRequest("GET", order.Certificate, nil)
	if err != nil {
		return nil, err
	}
	request = request.WithContext(ctx)
	for n := 0; ; n++ {
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				return nil, err
			}
		}
		if response.StatusCode == http.StatusOK {
			defer response.Body.Close()
			certificateData, err := ioutil.ReadAll(response.Body)
			if err != nil {
				return nil, err
			}
			return &certificateData, nil
		}
		response.Body.Close()
		err = waitForRetry(ctx, n, response)
		if err != nil {
			return nil, err
		}
	}
}

type dnsResultOkay func(*dnsQueryResult) bool

func getDNS(ctx context.Context, name, rrType string, ok dnsResultOkay) (*[]dnsQueryAnswer, error) {
	request, err := http.NewRequest("GET", "https://dns.google/resolve?name="+name+"&type="+rrType, nil)
	if err != nil {
		return nil, err
	}
	request = request.WithContext(ctx)
	n := 0
	for {
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				return nil, err
			}
		}
		if response.StatusCode == http.StatusOK {
			dnsResult := dnsQueryResult{}
			err := json.NewDecoder(response.Body).Decode(&dnsResult)
			response.Body.Close()
			if err != nil {
				return nil, err
			}
			if dnsResult.Status != 0 {
				return nil, errors.New("DNS Result error")
			}
			if ok(&dnsResult) {
				return &dnsResult.Answer, nil
			}
			minTTL := 60
			for _, answer := range dnsResult.Answer {
				if answer.TTL < minTTL {
					minTTL = answer.TTL
				}
			}
			if err := waitForTTL(ctx, time.Duration(minTTL)*time.Second); err != nil {
				return nil, err
			}
			continue
		}
		response.Body.Close()
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusInternalServerError || response.StatusCode == http.StatusBadGateway {
			if err := waitForRetry(ctx, n, response); err != nil {
				return nil, err
			}
			n++
			continue
		}
		return nil, errors.New("DNS Query Failed")
	}
}
