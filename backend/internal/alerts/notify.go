package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// Notifier delivers new alerts to an external webhook (Slack-style {text}).
// The URL is operator-configured, so it is trusted (no SSRF gating needed).
type Notifier struct {
	url    string
	client *http.Client
	log    *slog.Logger
}

// NewNotifier returns a notifier; delivery is a no-op when url is empty.
func NewNotifier(url string, log *slog.Logger) *Notifier {
	if log == nil {
		log = slog.Default()
	}
	return &Notifier{url: url, client: &http.Client{Timeout: 10 * time.Second}, log: log}
}

// Enabled reports whether a webhook is configured.
func (n *Notifier) Enabled() bool { return n != nil && n.url != "" }

// Deliver posts the alerts to the webhook as JSON {text, alerts}. It returns an
// error on failure so the caller can leave them pending for the next attempt.
func (n *Notifier) Deliver(ctx context.Context, alerts []db.Alert) error {
	if !n.Enabled() || len(alerts) == 0 {
		return nil
	}
	payload := map[string]any{"text": summarize(alerts), "alerts": alerts}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	n.log.Info("alerts delivered to webhook", "count", len(alerts))
	return nil
}

// summarize builds a human-readable message for the webhook's text field.
func summarize(alerts []db.Alert) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🚨 Pahredar: %d new alert", len(alerts))
	if len(alerts) != 1 {
		b.WriteString("s")
	}
	b.WriteString("\n")
	const max = 10
	for i, a := range alerts {
		if i >= max {
			fmt.Fprintf(&b, "…and %d more", len(alerts)-max)
			break
		}
		fmt.Fprintf(&b, "• %s", a.Title)
		if a.CVEID != "" {
			fmt.Fprintf(&b, " (%s)", a.CVEID)
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
