package ACME2_CertProvider

import (
	"container/list"
	"context"
	"errors"
	"net/http"
	"sync"
)

const maxNonce = 100

var (
	pool  = list.New()
	mutex sync.Mutex
)

func getNonce(ctx context.Context) (string, error) {
	mutex.Lock()
	defer mutex.Unlock()
	nonce := pool.Front()
	if nonce != nil {
		pool.Remove(nonce)
		return nonce.Value.(string), nil
	}
	return fetchNonce(ctx)
}

func fetchNonce(ctx context.Context) (string, error) {
	directory, ok := ctx.Value(ctxDirectory).(*directory)
	if !ok {
		return "", errors.New("Cannot get directory")
	}
	request, err := http.NewRequest("HEAD", directory.NewNonce, nil)
	if err != nil {
		return "", err
	}
	request = request.WithContext(ctx)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	nonce := response.Header.Get("Replay-Nonce")
	if nonce == "" {
		if response.StatusCode > 299 {
			return "", responseError(response)
		}
		return "", errors.New("acme: nonce not found")
	}
	return nonce, nil
}

func clearNonce() {
	mutex.Lock()
	defer mutex.Unlock()
	pool.Init()
}

func addNonce(header http.Header) {
	nonce := header.Get("Replay-Nonce")
	if nonce == "" {
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	if pool.Len() >= maxNonce {
		if front := pool.Front(); front != nil {
			pool.Remove(front)
		}
	}
	pool.PushBack(nonce)
}
