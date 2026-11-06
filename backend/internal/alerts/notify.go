package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// Mail is the SMTP configuration for email alert delivery.
type Mail struct {
	Host, Port, Username, Password, From, To string
}

func (m Mail) enabled() bool { return m.Host != "" && m.To != "" }

// Notifier delivers new alerts to the configured channels — a webhook
// (Slack-style {text}) and/or email. Operator-configured, so trusted.
type Notifier struct {
	webhookURL string
	mail       Mail
	client     *http.Client
	log        *slog.Logger
}

// NewNotifier returns a notifier; delivery is a no-op when nothing is configured.
func NewNotifier(webhookURL string, mail Mail, log *slog.Logger) *Notifier {
	if log == nil {
		log = slog.Default()
	}
	return &Notifier{webhookURL: webhookURL, mail: mail, client: &http.Client{Timeout: 10 * time.Second}, log: log}
}

// Enabled reports whether any delivery channel is configured.
func (n *Notifier) Enabled() bool { return n != nil && (n.webhookURL != "" || n.mail.enabled()) }

// Deliver sends the alerts to every configured channel. It returns an error
// only when all channels fail, so a partial success still clears the queue;
// on total failure the caller leaves them pending to retry.
func (n *Notifier) Deliver(ctx context.Context, alerts []db.Alert) error {
	if !n.Enabled() || len(alerts) == 0 {
		return nil
	}
	text := summarize(alerts)
	channels, failures := 0, 0
	if n.webhookURL != "" {
		channels++
		if err := n.sendWebhook(ctx, text, alerts); err != nil {
			n.log.Warn("alert webhook delivery failed", "err", err)
			failures++
		}
	}
	if n.mail.enabled() {
		channels++
		if err := n.sendEmail(text, alerts); err != nil {
			n.log.Warn("alert email delivery failed", "err", err)
			failures++
		}
	}
	if channels > 0 && failures == channels {
		return fmt.Errorf("all %d delivery channel(s) failed", channels)
	}
	n.log.Info("alerts delivered", "count", len(alerts), "channels", channels-failures)
	return nil
}

func (n *Notifier) sendWebhook(ctx context.Context, text string, alerts []db.Alert) error {
	body, err := json.Marshal(map[string]any{"text": text, "alerts": alerts})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhookURL, bytes.NewReader(body))
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
	return nil
}

func (n *Notifier) sendEmail(text string, alerts []db.Alert) error {
	m := n.mail
	var auth smtp.Auth
	if m.Username != "" {
		auth = smtp.PlainAuth("", m.Username, m.Password, m.Host)
	}
	subject := fmt.Sprintf("Pahredar: %d new alert", len(alerts))
	if len(alerts) != 1 {
		subject += "s"
	}
	msg := buildEmail(m.From, m.To, subject, text)
	return smtp.SendMail(net.JoinHostPort(m.Host, m.Port), auth, m.From, []string{m.To}, msg)
}

func buildEmail(from, to, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	b.WriteString("\r\n")
	return []byte(b.String())
}

// summarize builds a human-readable message for the webhook/email body.
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
		if a.CVEID != "" && !strings.HasPrefix(a.CVEID, "finding:") {
			fmt.Fprintf(&b, " (%s)", a.CVEID)
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
