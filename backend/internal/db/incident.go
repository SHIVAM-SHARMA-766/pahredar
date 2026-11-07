package db

import (
	"context"
	"strconv"
	"time"
)

// Incident is a per-asset rollup of its current problems (the asset's alert
// rows are its items). One open incident per asset. See docs/phase4.md.
type Incident struct {
	ID             int64      `json:"id"`
	AssetID        int64      `json:"asset_id"`
	ClientID       *int64     `json:"client_id,omitempty"`
	Status         string     `json:"status"`
	Severity       string     `json:"severity"`
	Title          string     `json:"title"`
	ItemCount      int        `json:"item_count"`
	OpenedAt       time.Time  `json:"opened_at"`
	LastEventAt    time.Time  `json:"last_event_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	ReadAt         *time.Time `json:"read_at,omitempty"`
	// Joined for display.
	AssetValue string `json:"asset_value,omitempty"`
	ClientName string `json:"client_name,omitempty"`
}

// RefreshIncidents rolls each asset's alert rows up into a single open incident:
// it upserts one incident per asset that has alerts, recomputing severity, title
// and item count. When new alerts have appeared since the incident last changed,
// it re-surfaces the incident (clears read_at) and re-queues it for delivery
// (clears delivered_at). Safe to run repeatedly.
func (s *Store) RefreshIncidents(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO incident (asset_id, client_id, severity, title, item_count, last_event_at, status)
		SELECT al.asset_id, a.client_id,
		       (ARRAY['info','low','medium','high','critical'])[max(
		           CASE al.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END)],
		       'Issues on ' || a.value,
		       count(*),
		       max(al.created_at),
		       'triggered'
		FROM alert al JOIN asset a ON a.id = al.asset_id
		GROUP BY al.asset_id, a.client_id, a.value
		ON CONFLICT (asset_id) WHERE status <> 'resolved'
		DO UPDATE SET
		    severity     = EXCLUDED.severity,
		    title        = EXCLUDED.title,
		    item_count   = EXCLUDED.item_count,
		    client_id    = EXCLUDED.client_id,
		    read_at      = CASE WHEN EXCLUDED.last_event_at > incident.last_event_at THEN NULL ELSE incident.read_at END,
		    delivered_at = CASE WHEN EXCLUDED.last_event_at > incident.last_event_at THEN NULL ELSE incident.delivered_at END,
		    last_event_at = GREATEST(incident.last_event_at, EXCLUDED.last_event_at)`)
	return err
}

// incidentScope appends a client-scope filter; allClients bypasses it.
func incidentScope(allClients bool, clientIDs []int64, args *[]any) string {
	if allClients {
		return ""
	}
	if len(clientIDs) == 0 {
		return " AND false" // no access → no rows
	}
	*args = append(*args, clientIDs)
	return " AND i.client_id = ANY($1)"
}

// ListIncidents returns incidents newest activity first, scoped to the caller's
// clients. Resolved incidents are included (the UI can filter).
func (s *Store) ListIncidents(ctx context.Context, allClients bool, clientIDs []int64, limit int) ([]Incident, error) {
	args := []any{}
	scope := incidentScope(allClients, clientIDs, &args)
	args = append(args, limit)
	q := `
		SELECT i.id, i.asset_id, i.client_id, i.status, i.severity, i.title, i.item_count,
		       i.opened_at, i.last_event_at, i.acknowledged_at, i.resolved_at, i.read_at,
		       COALESCE(a.value, ''), COALESCE(c.name, '')
		FROM incident i
		JOIN asset a ON a.id = i.asset_id
		LEFT JOIN client c ON c.id = i.client_id
		WHERE true` + scope + `
		ORDER BY i.last_event_at DESC LIMIT $` + strconv.Itoa(len(args))
	return s.queryIncidents(ctx, q, args...)
}

// GetIncident returns one incident with joined display fields.
func (s *Store) GetIncident(ctx context.Context, id int64) (*Incident, error) {
	out, err := s.queryIncidents(ctx, `
		SELECT i.id, i.asset_id, i.client_id, i.status, i.severity, i.title, i.item_count,
		       i.opened_at, i.last_event_at, i.acknowledged_at, i.resolved_at, i.read_at,
		       COALESCE(a.value, ''), COALESCE(c.name, '')
		FROM incident i
		JOIN asset a ON a.id = i.asset_id
		LEFT JOIN client c ON c.id = i.client_id
		WHERE i.id = $1`, id)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return &out[0], nil
}

func (s *Store) queryIncidents(ctx context.Context, q string, args ...any) ([]Incident, error) {
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Incident{}
	for rows.Next() {
		var i Incident
		if err := rows.Scan(&i.ID, &i.AssetID, &i.ClientID, &i.Status, &i.Severity, &i.Title, &i.ItemCount,
			&i.OpenedAt, &i.LastEventAt, &i.AcknowledgedAt, &i.ResolvedAt, &i.ReadAt, &i.AssetValue, &i.ClientName); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// IncidentItems returns the alert rows rolled up by an incident (its asset's).
func (s *Store) IncidentItems(ctx context.Context, assetID int64) ([]Alert, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT al.id, al.type, al.asset_id, al.cve_id, al.severity, al.title, al.detail, al.created_at, al.read_at, ''
		FROM alert al WHERE al.asset_id = $1 ORDER BY al.created_at DESC`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.Type, &a.AssetID, &a.CVEID, &a.Severity, &a.Title, &a.Detail, &a.CreatedAt, &a.ReadAt, &a.AssetValue); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// MarkIncidentRead marks one incident read (or all when id is 0).
func (s *Store) MarkIncidentRead(ctx context.Context, id int64) error {
	if id == 0 {
		_, err := s.pool.Exec(ctx, `UPDATE incident SET read_at = now() WHERE read_at IS NULL`)
		return err
	}
	_, err := s.pool.Exec(ctx, `UPDATE incident SET read_at = now() WHERE id = $1 AND read_at IS NULL`, id)
	return err
}

// MarkAllIncidentsRead marks every unread incident in the caller's scope read.
func (s *Store) MarkAllIncidentsRead(ctx context.Context, allClients bool, clientIDs []int64) error {
	args := []any{}
	scope := incidentScope(allClients, clientIDs, &args)
	_, err := s.pool.Exec(ctx, `UPDATE incident i SET read_at = now() WHERE i.read_at IS NULL`+scope, args...)
	return err
}

// UnreadIncidentCount counts unread incidents in the caller's scope.
func (s *Store) UnreadIncidentCount(ctx context.Context, allClients bool, clientIDs []int64) (int, error) {
	args := []any{}
	scope := incidentScope(allClients, clientIDs, &args)
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM incident i WHERE i.read_at IS NULL`+scope, args...).Scan(&n)
	return n, err
}

// PendingIncidents returns incidents not yet delivered, oldest activity first.
func (s *Store) PendingIncidents(ctx context.Context, limit int) ([]Incident, error) {
	return s.queryIncidents(ctx, `
		SELECT i.id, i.asset_id, i.client_id, i.status, i.severity, i.title, i.item_count,
		       i.opened_at, i.last_event_at, i.acknowledged_at, i.resolved_at, i.read_at,
		       COALESCE(a.value, ''), COALESCE(c.name, '')
		FROM incident i
		JOIN asset a ON a.id = i.asset_id
		LEFT JOIN client c ON c.id = i.client_id
		WHERE i.delivered_at IS NULL
		ORDER BY i.last_event_at LIMIT $1`, limit)
}

// MarkIncidentsDelivered stamps the given incidents delivered.
func (s *Store) MarkIncidentsDelivered(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx, `UPDATE incident SET delivered_at = now() WHERE id = ANY($1)`, ids)
	return err
}
