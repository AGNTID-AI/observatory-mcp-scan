package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agntid/observatory/api/internal/domain"
)

type FileArtifacts struct{ Root string }

func (f FileArtifacts) Put(_ context.Context, assessmentID, name, contentType string, r io.Reader) (domain.Artifact, error) {
	name = filepath.Base(name)
	dir := filepath.Join(f.Root, assessmentID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return domain.Artifact{}, err
	}
	path := filepath.Join(dir, name)
	tmp := path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return domain.Artifact{}, err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(r, 25<<20))
	closeErr := out.Close()
	if copyErr != nil {
		return domain.Artifact{}, copyErr
	}
	if closeErr != nil {
		return domain.Artifact{}, closeErr
	}
	if err := os.Rename(tmp, path); err != nil {
		return domain.Artifact{}, err
	}
	parts := strings.Split(name, ".")
	format := parts[len(parts)-1]
	kind := "technical"
	if strings.Contains(name, "executive") {
		kind = "executive"
	}
	if format == "json" {
		kind = "canonical"
	}
	if format == "sarif" {
		kind = "ci"
	}
	return domain.Artifact{ID: name, Name: name, Format: format, Kind: kind, ContentType: contentType, Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), CreatedAt: time.Now().UTC()}, nil
}
func (f FileArtifacts) Open(_ context.Context, assessmentID, id string) (io.ReadCloser, domain.Artifact, error) {
	id = filepath.Base(id)
	path := filepath.Join(f.Root, assessmentID, id)
	r, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, domain.Artifact{}, ErrNotFound
		}
		return nil, domain.Artifact{}, err
	}
	info, _ := r.Stat()
	ct := "application/octet-stream"
	if strings.HasSuffix(id, ".json") {
		ct = "application/json"
	}
	if strings.HasSuffix(id, ".sarif") {
		ct = "application/sarif+json"
	}
	if strings.HasSuffix(id, ".html") {
		ct = "text/html; charset=utf-8"
	}
	if strings.HasSuffix(id, ".md") {
		ct = "text/markdown; charset=utf-8"
	}
	return r, domain.Artifact{ID: id, Name: id, ContentType: ct, Size: info.Size()}, nil
}
