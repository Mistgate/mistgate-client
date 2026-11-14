package ipc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/mistgate/mistgate-client/core/internal/ipcsize"
)

const MaxLineBytes = ipcsize.MaxLineBytes

var ErrLineTooLong = errors.New("JSON line exceeds the one MiB limit")
var ErrUnterminatedLine = errors.New("JSON line is missing its newline")

func ReadLine(reader *bufio.Reader) ([]byte, error) {
	line := make([]byte, 0, 4096)
	for {
		fragment, err := reader.ReadSlice('\n')
		payload := fragment
		terminated := err == nil
		if terminated {
			payload = payload[:len(payload)-1]
		}
		if len(line)+len(payload) > MaxLineBytes {
			return nil, ErrLineTooLong
		}
		line = append(line, payload...)
		if terminated {
			return line, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			if len(line) == 0 {
				return nil, io.EOF
			}
			return nil, ErrUnterminatedLine
		}
		return nil, err
	}
}

type Request struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type RPCError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Response struct {
	ID     json.RawMessage `json:"id"`
	Result any             `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
}

func ParseRequest(line []byte) (Request, *RPCError) {
	var request Request
	if !utf8.Valid(line) {
		return request, badParams()
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	if err := decoder.Decode(&request); err != nil {
		return request, badParams()
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return request, badParams()
	}
	if len(request.ID) == 0 || !validID(request.ID) || request.Method == "" {
		return request, badParams()
	}
	return request, nil
}

func validID(id json.RawMessage) bool {
	var value any
	if err := json.Unmarshal(id, &value); err != nil {
		return false
	}
	switch value.(type) {
	case string, float64:
		return true
	default:
		return false
	}
}

func MarshalResponse(response Response) ([]byte, error) {
	line, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("marshal IPC response: %w", err)
	}
	return append(line, '\n'), nil
}

func badParams() *RPCError {
	return &RPCError{Code: "bad_params", Message: "request parameters are invalid"}
}
