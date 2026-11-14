package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestUntrustedConnectionGetsOneAnswer(t *testing.T) {
	service, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		(&Server{}).ServeConn(context.Background(), service, false)
		close(done)
	}()

	if _, err := client.Write([]byte("{\"id\":1,\"method\":\"hello\"}\n")); err != nil {
		t.Fatal("untrusted request was not answered")
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	line, err := ReadLine(bufio.NewReader(client))
	if err != nil {
		t.Fatal("untrusted answer was not readable")
	}
	var response Response
	if json.Unmarshal(line, &response) != nil || response.Error == nil || response.Error.Code != "not_trusted" {
		t.Fatal("untrusted request did not receive the refusal answer")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("untrusted connection remained open after its answer")
	}
}

func TestClientDoesNotQueueAnOversizedIPCFrame(t *testing.T) {
	service, peer := net.Pipe()
	client := newClient(service, 1)
	defer client.close()
	defer peer.Close()

	line := make([]byte, MaxLineBytes+2)
	line[len(line)-1] = '\n'
	if client.enqueue(line) {
		t.Fatal("oversized IPC frame entered the output queue")
	}
	select {
	case <-client.done:
	default:
		t.Fatal("oversized IPC frame did not close the connection")
	}
}
