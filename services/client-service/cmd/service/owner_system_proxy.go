package main

import (
	"encoding/json"
	"errors"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"io"
)

// A one-shot owner-user worker. The primary process SID is checked by WinINET
// wrappers. No manifest, IPC token, filesystem path or network input is accepted.
func runOwnerSystemProxy(input io.Reader, output io.Writer) error {
	decoder := json.NewDecoder(io.LimitReader(input, 512*1024))
	decoder.DisallowUnknownFields()
	var command wp.OwnerProxyCommand
	if decoder.Decode(&command) != nil || command.Owner == "" || (command.Expected == nil) != (command.Desired == nil) {
		return errors.New("OWNER_PROXY_COMMAND_INVALID")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("OWNER_PROXY_COMMAND_INVALID")
	}
	var reply wp.OwnerProxyReply
	var err error
	if command.Desired != nil {
		err = wp.CompareSetOwnerSystemProxy(command.Owner, *command.Expected, *command.Desired)
	}
	if err == nil {
		reply.State, err = wp.ReadOwnerSystemProxy(command.Owner)
	}
	if err != nil {
		reply.Error = err.Error()
	}
	return json.NewEncoder(output).Encode(reply)
}
