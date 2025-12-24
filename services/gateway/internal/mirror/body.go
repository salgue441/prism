// Package mirror provides traffic mirroring functionality for the gateway.
package mirror

import (
	"bytes"
	"io"
)

// CloneBody reads the request body and returns two ReadClosers:
// one for the original request and one for the mirror request.
// If the body exceeds maxSize, it returns an error.
func CloneBody(body io.ReadCloser, maxSize int64) (original io.ReadCloser, clonedBytes []byte, err error) {
	if body == nil {
		return nil, nil, nil
	}

	// Read body with size limit
	var reader io.Reader = body
	if maxSize > 0 {
		reader = io.LimitReader(body, maxSize+1) // +1 to detect overflow
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		body.Close()
		return nil, nil, err
	}

	// Close original body
	body.Close()

	// Check if body exceeded max size
	if maxSize > 0 && int64(len(data)) > maxSize {
		// Return original body but don't clone (too large)
		return io.NopCloser(bytes.NewReader(data)), nil, nil
	}

	// Return new ReadCloser for original request and bytes for clone
	return io.NopCloser(bytes.NewReader(data)), data, nil
}

// CloneBodyForBoth reads the request body and returns two ReadClosers.
// This is useful when you need ReadClosers for both original and mirror.
func CloneBodyForBoth(body io.ReadCloser, maxSize int64) (original, clone io.ReadCloser, err error) {
	if body == nil {
		return nil, nil, nil
	}

	// Read body with size limit
	var reader io.Reader = body
	if maxSize > 0 {
		reader = io.LimitReader(body, maxSize+1)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		body.Close()
		return nil, nil, err
	}

	// Close original body
	body.Close()

	// Check if body exceeded max size
	if maxSize > 0 && int64(len(data)) > maxSize {
		// Return original only, clone is nil (too large to mirror)
		return io.NopCloser(bytes.NewReader(data)), nil, nil
	}

	// Return two ReadClosers from the buffered data
	return io.NopCloser(bytes.NewReader(data)), io.NopCloser(bytes.NewReader(data)), nil
}
