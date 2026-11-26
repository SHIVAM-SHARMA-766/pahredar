package easm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/SHIVAM-SHARMA-766/pahredar/backend/internal/db"
)

// rdap collects domain registration intelligence via RDAP (passive, free, no
// key). Spec P01. rdap.org bootstraps to the authoritative RDAP server.
type rdap struct{ client *http.Client }

func (rdap) Name() string { return "rdap" }

type rdapResp struct {
	LDHName     string           `json:"ldhName"`
	Status      []string         `json:"status"`
	Events      []rdapEvent      `json:"events"`
	Nameservers []rdapNameserver `json:"nameservers"`
	Entities    []rdapEntity     `json:"entities"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}
type rdapNameserver struct {
	LDHName string `json:"ldhName"`
}
type rdapEntity struct {
	Roles      []string          `json:"roles"`
	Handle     string            `json:"handle"`
	VCardArray []json.RawMessage `json:"vcardArray"`
}

func (r rdap) Collect(ctx context.Context, domain string) ([]db.AssetRecord, error) {
	var resp rdapResp
	if err := getJSON(ctx, r.client, "https://rdap.org/domain/"+domain, &resp); err != nil {
		return nil, fmt.Errorf("rdap: %w", err)
	}

	events := map[string]string{}
	for _, e := range resp.Events {
		events[e.Action] = e.Date
	}
	registrar := ""
	for _, ent := range resp.Entities {
		if contains(ent.Roles, "registrar") {
			registrar = vcardName(ent.VCardArray)
			if registrar == "" {
				registrar = ent.Handle
			}
			break
		}
	}

	out := []db.AssetRecord{rec("whois", "registration", "rdap", map[string]any{
		"domain":    resp.LDHName,
		"registrar": registrar,
		"created":   events["registration"],
		"expires":   events["expiration"],
		"updated":   events["last changed"],
		"status":    resp.Status,
	}, "RDAP")}

	for _, ns := range resp.Nameservers {
		name := strings.ToLower(strings.TrimSuffix(ns.LDHName, "."))
		if name == "" {
			continue
		}
		out = append(out, rec("nameserver", name, "rdap", map[string]any{"host": name}, "RDAP"))
	}
	return out, nil
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// vcardName extracts the "fn" (full name) from a jCard vcardArray, best-effort.
// Shape: ["vcard", [ ["fn", {}, "text", "Name"], ... ]].
func vcardName(vcard []json.RawMessage) string {
	if len(vcard) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if err := json.Unmarshal(vcard[1], &props); err != nil {
		return ""
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var name string
		if json.Unmarshal(p[0], &name) == nil && name == "fn" {
			var val string
			if json.Unmarshal(p[3], &val) == nil {
				return val
			}
		}
	}
	return ""
}
