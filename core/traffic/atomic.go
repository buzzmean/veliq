// Package traffic contains bounded accounting only. Its data never authorizes a
// route, changes TLS, or disables a required relay because a quota is unknown.
package traffic

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const maxFile = 1024 * 1024

func read(path string, out any) error {
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Size() > maxFile {
		return errors.New("TRAFFIC_STATE_INVALID")
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, maxFile+1))
	d.DisallowUnknownFields()
	if e = d.Decode(out); e != nil {
		return e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("TRAFFIC_STATE_TRAILING_DATA")
	}
	return nil
}
func write(path string, v any) error {
	if path == "" {
		return nil
	}
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > maxFile {
		return errors.New("TRAFFIC_STATE_LIMIT")
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".traffic-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
