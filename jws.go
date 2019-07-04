package ACME2_CertProvider

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ed25519"
)

var errUnsupportedKey = errors.New("acme: unknown key type; only RSA, ECDSA and ED25519 are supported")

func jwsEncodeJSON(key crypto.Signer, url, kid, nonce string, data interface{}) ([]byte, error) {
	alg, sha := jwsHasher(key)
	if alg == "" || !(sha.Available() || sha == 0) {
		return nil, errUnsupportedKey
	}
	var phead string
	if kid == "" {
		jwk, err := jwkEncode(key.Public())
		if err != nil {
			return nil, err
		}
		phead = fmt.Sprintf(`{"alg":%q,"jwk":%s,"nonce":%q,"url":%q}`, alg, jwk, nonce, url)
	} else {
		phead = fmt.Sprintf(`{"alg":%q,"kid":%q,"nonce":%q,"url":%q}`, alg, kid, nonce, url)
	}
	phead = base64.RawURLEncoding.EncodeToString([]byte(phead))
	cs, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	payload := base64.RawURLEncoding.EncodeToString(cs)
	dataToSign := []byte(fmt.Sprintf("%s.%s", phead, payload))
	sig, err := jwsSign(key, sha, dataToSign)
	if err != nil {
		return nil, err
	}
	return json.Marshal(&jws{
		Protected: phead,
		Payload:   payload,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	})
}

func jwkEncode(pub crypto.PublicKey) (jwk string, err error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		// https://tools.ietf.org/html/rfc7518#section-6.3.1
		n := pub.N
		e := big.NewInt(int64(pub.E))
		// Field order is important.
		// See https://tools.ietf.org/html/rfc7638#section-3.3 for details.
		jwk = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
			base64.RawURLEncoding.EncodeToString(e.Bytes()),
			base64.RawURLEncoding.EncodeToString(n.Bytes()),
		)
	case *ecdsa.PublicKey:
		// https://tools.ietf.org/html/rfc7518#section-6.2.1
		p := pub.Curve.Params()
		n := p.BitSize / 8
		if p.BitSize%8 != 0 {
			n++
		}
		x := pub.X.Bytes()
		if n > len(x) {
			x = append(make([]byte, n-len(x)), x...)
		}
		y := pub.Y.Bytes()
		if n > len(y) {
			y = append(make([]byte, n-len(y)), y...)
		}
		// Field order is important.
		// See https://tools.ietf.org/html/rfc7638#section-3.3 for details.
		jwk = fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`,
			p.Name,
			base64.RawURLEncoding.EncodeToString(x),
			base64.RawURLEncoding.EncodeToString(y),
		)
	case ed25519.PublicKey:
		// https://tools.ietf.org/html/rfc8037
		// Field order is important.
		// See https://tools.ietf.org/html/rfc7638#section-3.3 for details.
		jwk = fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`,
			base64.RawURLEncoding.EncodeToString(pub),
		)
	default:
		err = errUnsupportedKey
	}
	return
}

func jwsHasher(key crypto.Signer) (name string, hash crypto.Hash) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		name = "RS256"
		hash = crypto.SHA256
	case *ecdsa.PrivateKey:
		switch key.Params().Name {
		case "P-256":
			name = "ES256"
			hash = crypto.SHA256
		case "P-384":
			name = "ES384"
			hash = crypto.SHA384
		case "P-521":
			name = "ES512"
			hash = crypto.SHA512
		}
	case ed25519.PrivateKey:
		name = "EdDSA"
		hash = crypto.Hash(0)
	}
	return
}

func jwsSign(key crypto.Signer, sha crypto.Hash, data []byte) (result []byte, err error) {
	switch key := key.(type) {
	case *rsa.PrivateKey:
		hash := sha.New()
		hash.Write(data)
		result, err = key.Sign(rand.Reader, hash.Sum(nil), sha)
	case *ecdsa.PrivateKey:
		hash := sha.New()
		hash.Write(data)
		r, s, err := ecdsa.Sign(rand.Reader, key, hash.Sum(nil))
		if err != nil {
			break
		}
		rb, sb := r.Bytes(), s.Bytes()
		size := key.Params().BitSize / 8
		if size%8 > 0 {
			size++
		}
		result = make([]byte, size*2)
		copy(result[size-len(rb):], rb)
		copy(result[size*2-len(sb):], sb)
	case ed25519.PrivateKey:
		result, err = key.Sign(rand.Reader, data, sha)
	}
	return
}

func jwkThumbprint(pub crypto.PublicKey) (string, error) {
	jwk, err := jwkEncode(pub)
	if err != nil {
		return "", err
	}
	b := sha256.Sum256([]byte(jwk))
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
