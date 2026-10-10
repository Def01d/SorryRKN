package core

import (
	"encoding/json"
	"os"
	"time"
)

// TelegramHealth is produced only after a nonce-checked MTProto exchange through
// the local listener. Opening its TCP port is deliberately not a health check.
type TelegramHealth struct {
	State       string                      `json:"state"`
	LatencyMS   float64                     `json:"latency_ms,omitempty"`
	CheckedAt   string                      `json:"checked_at,omitempty"`
	Datacenters map[string]TelegramDCHealth `json:"datacenters,omitempty"`
	Error       string                      `json:"error,omitempty"`
}

type TelegramDCHealth struct {
	OK        bool    `json:"ok"`
	LatencyMS float64 `json:"latency_ms,omitempty"`
	Error     string  `json:"error,omitempty"`
}

func ReadTelegramHealth(path string, now time.Time) TelegramHealth {
	checking := TelegramHealth{State: "checking"}
	f, err := os.Open(path)
	if err != nil {
		return checking
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > 16384 {
		return checking
	}
	var health TelegramHealth
	if json.NewDecoder(f).Decode(&health) != nil {
		return checking
	}
	switch health.State {
	case "ready", "degraded", "unavailable":
	default:
		return checking
	}
	checked, err := time.Parse(time.RFC3339Nano, health.CheckedAt)
	if err != nil || now.Sub(checked) > 90*time.Second || checked.After(now.Add(5*time.Second)) {
		return TelegramHealth{State: "checking", Error: "health report expired"}
	}
	// Do not accept a bare readiness claim without any verified datacenter.
	good := 0
	for _, dc := range health.Datacenters {
		if dc.OK {
			good++
		}
	}
	if len(health.Datacenters) == 0 {
		return checking
	}
	if good == 0 {
		health.State = "unavailable"
	} else if good < len(health.Datacenters) {
		health.State = "degraded"
	} else {
		health.State = "ready"
	}
	return health
}

func applyServiceHealth(s *State, baseStatus, baseDetail string) {
	s.Status, s.Detail = baseStatus, baseDetail
	if s.Telegram && s.TelegramHealth.State != "ready" {
		s.Status = "partial"
		switch s.TelegramHealth.State {
		case "degraded":
			s.Detail = "Telegram: доступны не все дата-центры"
		case "unavailable":
			s.Detail = "Telegram не отвечает · ищем маршрут"
		default:
			s.Detail = "Проверяем ответ Telegram"
		}
	}
	for _, target := range s.Services {
		if !target.OK {
			s.Status = "partial"
			s.Detail = target.Name + ": доступ не подтверждён · см. диагностику"
			break
		}
	}
}
