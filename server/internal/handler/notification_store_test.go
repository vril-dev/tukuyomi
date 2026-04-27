package handler

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNotificationManagerTransitions(t *testing.T) {
	var (
		mu      sync.Mutex
		states  []string
		sources []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode webhook body: %v", err)
		}
		mu.Lock()
		states = append(states, stringValue(body["state"]))
		sources = append(sources, stringValue(body["source"]))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	mgr := newNotificationManager("test")
	mgr.Update(notificationConfig{
		Enabled:         true,
		CooldownSeconds: 0,
		Sinks: []notificationSinkConfig{
			{
				Name:       "webhook",
				Type:       notificationSinkTypeWebhook,
				Enabled:    true,
				WebhookURL: srv.URL,
				TimeoutSec: 5,
			},
		},
		Upstream: notificationTriggerConfig{
			Enabled:            true,
			WindowSeconds:      1,
			ActiveThreshold:    1,
			EscalatedThreshold: 2,
		},
		Security: notificationSecurityTrigger{
			Enabled:            true,
			WindowSeconds:      1,
			ActiveThreshold:    1,
			EscalatedThreshold: 2,
			Sources:            []string{"rate_limited"},
		},
	})

	start := time.Unix(1700000000, 0).UTC()
	mgr.Observe(notificationObservation{
		Category:   notificationCategorySecurity,
		Source:     "rate_limited",
		Path:       "/login",
		RemoteIP:   "203.0.113.10",
		ObservedAt: start,
	})
	mgr.flushExpired(start.Add(1100 * time.Millisecond))

	mgr.Observe(notificationObservation{
		Category:   notificationCategorySecurity,
		Source:     "rate_limited",
		Path:       "/login",
		RemoteIP:   "203.0.113.10",
		ObservedAt: start.Add(1200 * time.Millisecond),
	})
	mgr.Observe(notificationObservation{
		Category:   notificationCategorySecurity,
		Source:     "rate_limited",
		Path:       "/login",
		RemoteIP:   "203.0.113.11",
		ObservedAt: start.Add(1400 * time.Millisecond),
	})
	mgr.flushExpired(start.Add(2200 * time.Millisecond))
	mgr.flushExpired(start.Add(3200 * time.Millisecond))

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		got := append([]string(nil), states...)
		src := append([]string(nil), sources...)
		mu.Unlock()
		if len(got) >= 3 {
			wantCounts := map[string]int{
				notificationStateActive:    1,
				notificationStateEscalated: 1,
				notificationStateQuiet:     1,
			}
			gotCounts := map[string]int{}
			for i := range got {
				gotCounts[got[i]]++
				if src[i] != "rate_limited" {
					t.Fatalf("sources[%d]=%q want=rate_limited all=%v", i, src[i], src)
				}
			}
			for state, want := range wantCounts {
				if gotCounts[state] < want {
					t.Fatalf("missing state %q counts=%v all=%v", state, gotCounts, got)
				}
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for webhook notifications, got=%v", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSendNotificationEmailDeliversToSMTPServer(t *testing.T) {
	smtpServer := newTestSMTPServer(t)
	dispatch := notificationDispatch{
		Product:    "tukuyomi-test",
		Category:   notificationCategorySecurity,
		Source:     "rate_limited",
		State:      notificationStateActive,
		Title:      "[tukuyomi-test] rate limit active",
		Summary:    "notification email smoke",
		WindowSecs: 60,
		Count:      3,
		UniqueIPs:  2,
		TopPaths:   []string{"/login", "/admin"},
		MaxScore:   7,
	}

	err := sendNotificationEmail(notificationSinkConfig{
		Name:          "ops-email",
		Type:          notificationSinkTypeEmail,
		Enabled:       true,
		SMTPAddress:   smtpServer.addr,
		From:          "alerts@example.invalid",
		To:            []string{"secops@example.invalid"},
		SubjectPrefix: "[tukuyomi-test]",
	}, dispatch)
	if err != nil {
		t.Fatalf("sendNotificationEmail: %v", err)
	}

	select {
	case msg := <-smtpServer.messages:
		for _, want := range []string{
			"From: alerts@example.invalid",
			"To: secops@example.invalid",
			"Subject: [tukuyomi-test] [tukuyomi-test] rate limit active",
			"notification email smoke",
			"Category: security",
			"Source: rate_limited",
			"State: active",
			"Window: 60s",
			"Count: 3",
			"Unique IPs: 2",
			"Top paths: /login, /admin",
			"Max score: 7",
		} {
			if !strings.Contains(msg, want) {
				t.Fatalf("email message missing %q: %q", want, msg)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SMTP message")
	}
}

type testSMTPServer struct {
	addr     string
	listener net.Listener
	messages chan string
}

func newTestSMTPServer(t *testing.T) *testSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen smtp: %v", err)
	}
	s := &testSMTPServer{
		addr:     ln.Addr().String(),
		listener: ln,
		messages: make(chan string, 1),
	}
	t.Cleanup(func() {
		_ = ln.Close()
	})
	go s.serve(t)
	return s
}

func (s *testSMTPServer) serve(t *testing.T) {
	conn, err := s.listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	reader := bufio.NewReader(conn)
	writeLine := func(line string) {
		_, _ = conn.Write([]byte(line + "\r\n"))
	}
	writeLine("220 localhost ESMTP")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Errorf("smtp read command: %v", err)
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(cmd)
		switch {
		case strings.HasPrefix(upper, "EHLO ") || strings.HasPrefix(upper, "HELO "):
			writeLine("250 localhost")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			writeLine("250 ok")
		case strings.HasPrefix(upper, "RCPT TO:"):
			writeLine("250 ok")
		case upper == "DATA":
			writeLine("354 end with dot")
			var msg strings.Builder
			for {
				dataLine, err := reader.ReadString('\n')
				if err != nil {
					t.Errorf("smtp read data: %v", err)
					return
				}
				if strings.TrimRight(dataLine, "\r\n") == "." {
					break
				}
				msg.WriteString(dataLine)
			}
			s.messages <- msg.String()
			writeLine("250 queued")
		case upper == "QUIT":
			writeLine("221 bye")
			return
		default:
			t.Errorf("unexpected SMTP command: %q", cmd)
			writeLine("500 unexpected command")
			return
		}
	}
}
