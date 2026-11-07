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
	return n.postWebhook(ctx, map[string]any{"text": text, "alerts": alerts})
}

// postWebhook POSTs a JSON payload to the configured (env) webhook.
func (n *Notifier) postWebhook(ctx context.Context, payload any) error {
	return n.postWebhookTo(ctx, n.webhookURL, payload)
}

// postWebhookTo POSTs a JSON payload to an arbitrary webhook URL.
func (n *Notifier) postWebhookTo(ctx context.Context, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
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
	subject := fmt.Sprintf("Pahredar: %d new alert", len(alerts))
	if len(alerts) != 1 {
		subject += "s"
	}
	return n.sendMail(subject, text)
}

// sendMail sends a plain-text email to the configured (env) recipient.
func (n *Notifier) sendMail(subject, body string) error {
	return n.sendMailTo(n.mail.To, subject, body)
}

// sendMailTo sends a plain-text email to an arbitrary recipient using the
// configured SMTP server. Requires SMTP host configured.
func (n *Notifier) sendMailTo(to, subject, body string) error {
	m := n.mail
	if m.Host == "" || to == "" {
		return fmt.Errorf("email channel needs SMTP_HOST configured")
	}
	var auth smtp.Auth
	if m.Username != "" {
		auth = smtp.PlainAuth("", m.Username, m.Password, m.Host)
	}
	msg := buildEmail(m.From, to, subject, body)
	return smtp.SendMail(net.JoinHostPort(m.Host, m.Port), auth, m.From, []string{to}, msg)
}

// SMTPConfigured reports whether the SMTP server is set (needed for email channels).
func (n *Notifier) SMTPConfigured() bool { return n != nil && n.mail.Host != "" }

// Target is a resolved delivery destination (channel type + address).
type Target struct {
	Type   string
	Target string
}

// EnvTargets returns the delivery targets from the env config (ALERT_WEBHOOK_URL
// and SMTP + ALERT_EMAIL_TO), used as a fallback when no DB channels apply.
func (n *Notifier) EnvTargets() []Target {
	var t []Target
	if n == nil {
		return t
	}
	if n.webhookURL != "" {
		t = append(t, Target{Type: "webhook", Target: n.webhookURL})
	}
	if n.mail.enabled() {
		t = append(t, Target{Type: "email", Target: n.mail.To})
	}
	return t
}

// DeliverIncidentTo sends one incident to a single channel target (a webhook URL
// or an email address), chosen by typ.
func (n *Notifier) DeliverIncidentTo(ctx context.Context, typ, target string, inc db.Incident) error {
	text := summarizeIncidents([]db.Incident{inc})
	switch typ {
	case "webhook":
		return n.postWebhookTo(ctx, target, map[string]any{"text": text, "incidents": []db.Incident{inc}})
	case "email":
		subject := fmt.Sprintf("Pahredar incident: %s", inc.AssetValue)
		return n.sendMailTo(target, subject, text)
	default:
		return fmt.Errorf("unknown channel type %q", typ)
	}
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

// DeliverIncidents sends incident updates to every configured channel. Same
// semantics as Deliver: an error only when all channels fail.
func (n *Notifier) DeliverIncidents(ctx context.Context, incidents []db.Incident) error {
	if !n.Enabled() || len(incidents) == 0 {
		return nil
	}
	text := summarizeIncidents(incidents)
	channels, failures := 0, 0
	if n.webhookURL != "" {
		channels++
		if err := n.postWebhook(ctx, map[string]any{"text": text, "incidents": incidents}); err != nil {
			n.log.Warn("incident webhook delivery failed", "err", err)
			failures++
		}
	}
	if n.mail.enabled() {
		channels++
		subject := fmt.Sprintf("Pahredar: %d incident update", len(incidents))
		if len(incidents) != 1 {
			subject += "s"
		}
		if err := n.sendMail(subject, text); err != nil {
			n.log.Warn("incident email delivery failed", "err", err)
			failures++
		}
	}
	if channels > 0 && failures == channels {
		return fmt.Errorf("all %d delivery channel(s) failed", channels)
	}
	n.log.Info("incidents delivered", "count", len(incidents), "channels", channels-failures)
	return nil
}

// summarizeIncidents builds a human-readable message for incident delivery.
func summarizeIncidents(incidents []db.Incident) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🚨 Pahredar: %d incident update", len(incidents))
	if len(incidents) != 1 {
		b.WriteString("s")
	}
	b.WriteString("\n")
	const max = 10
	for i, inc := range incidents {
		if i >= max {
			fmt.Fprintf(&b, "…and %d more", len(incidents)-max)
			break
		}
		fmt.Fprintf(&b, "• [%s] %s — %d issue", strings.ToUpper(inc.Severity), inc.AssetValue, inc.ItemCount)
		if inc.ItemCount != 1 {
			b.WriteString("s")
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
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
