package management

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPIHome/internal/cluster"
	"gorm.io/gorm"
)

type codexDeviceRoundTripper func(*http.Request) (*http.Response, error)

func (f codexDeviceRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type failingCodexDeviceWriter struct {
	gin.ResponseWriter
	err error
}

func (w failingCodexDeviceWriter) Write([]byte) (int, error) {
	return 0, w.err
}

type failingCodexDeviceHTTPWriter struct {
	status int
	body   bytes.Buffer
	err    error
	header http.Header
}

func (w *failingCodexDeviceHTTPWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *failingCodexDeviceHTTPWriter) Write(body []byte) (int, error) {
	return w.body.Write(body)
}

func (w *failingCodexDeviceHTTPWriter) WriteHeader(status int) {
	w.status = status
}

func (w *failingCodexDeviceHTTPWriter) FlushError() error {
	if w.err == nil {
		return errors.New("transport flush failed")
	}
	return w.err
}

func (w *failingCodexDeviceHTTPWriter) Flush() {
	_ = w.FlushError()
}

type gatedCodexDeviceWriter struct {
	gin.ResponseWriter
	started   chan struct{}
	release   <-chan struct{}
	completed chan struct{}
}

func (w gatedCodexDeviceWriter) Write(body []byte) (int, error) {
	close(w.started)
	<-w.release
	n, errWrite := w.ResponseWriter.Write(body)
	close(w.completed)
	return n, errWrite
}

func onlyCodexOAuthSession(t *testing.T, db *gorm.DB) *cluster.OAuthSessionRecord {
	t.Helper()
	var sessions []cluster.OAuthSessionRecord
	if errFind := db.Find(&sessions).Error; errFind != nil {
		t.Fatal(errFind)
	}
	if len(sessions) != 1 {
		t.Fatalf("OAuth sessions = %d, want 1", len(sessions))
	}
	return &sessions[0]
}

func managementDeviceResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}
