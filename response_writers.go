// Thanks to https://github.com/authzed/prom-authzed-proxy/blob/main/cmd/prom-authzed-proxy/response_writers.go
// for the code

package main

import (
	"bytes"
	"net/http"
)

// filteredWriter wraps an http.ResponseWriter and resetting the values of any
// reserved headers.
type filteredWriter struct {
	savedHeaders map[string][]string
	http.ResponseWriter
}

// Compile-time assert that filteredWriter implements http.ResponseWriter.
var _ http.ResponseWriter = (*filteredWriter)(nil)

func (w filteredWriter) resetHeaders() {
	for name := range w.savedHeaders {
		w.ResponseWriter.Header().Del(name)
		for _, value := range w.savedHeaders[name] {
			w.ResponseWriter.Header().Add(name, value)
		}
	}
}

func (w filteredWriter) WriteHeader(code int) {
	w.resetHeaders()
	w.ResponseWriter.WriteHeader(code)
}

func (w filteredWriter) Write(b []byte) (int, error) {
	w.resetHeaders()
	return w.ResponseWriter.Write(b)
}

// logWriter wraps an http.ResponseWriter and logs the request and response
// metadata.
type logWriter struct {
	status int
	body   *bytes.Buffer
	http.ResponseWriter
}

// Compile-time assert that logWriter implements http.ResponseWriter.
var _ http.ResponseWriter = (*logWriter)(nil)

func (w *logWriter) WriteHeader(statusCode int) {
	w.status = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *logWriter) Write(b []byte) (int, error) {
	w.body = bytes.NewBuffer(b)
	return w.ResponseWriter.Write(b)
}

func logHandler(fn http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lw := &logWriter{0, nil, w}
		fn.ServeHTTP(lw, r)
	})
}
