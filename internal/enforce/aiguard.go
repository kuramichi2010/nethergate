package enforce

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// AIState is the enforcer's view of the AI: whether its actions are paused
// (quarantine) and why. It lives here, in the privileged process, so a
// hijacked AI cannot clear it.
type AIState struct {
	Paused bool      `json:"paused"`
	Reason string    `json:"reason,omitempty"`
	Since  time.Time `json:"since,omitempty"`
	By     string    `json:"by,omitempty"` // "quarantine" | "human"
	Mode   string    `json:"mode"`         // policy.ai.mode
}

func (s *Server) aiState() *AIState {
	st := s.ai
	st.Mode = s.Thresholds.AI.Mode
	return &st
}

func (s *Server) loadAIState() {
	if s.AIStatePath == "" {
		return
	}
	b, err := os.ReadFile(s.AIStatePath)
	if err != nil {
		return
	}
	var st AIState
	if json.Unmarshal(b, &st) == nil {
		s.ai = st
		if st.Paused {
			log.Printf("AI actions remain paused since %s (%s): %s", st.Since.Format(time.RFC3339), st.By, st.Reason)
		}
	}
}

// saveAIState persists the pause flag; caller holds s.mu.
func (s *Server) saveAIState() error {
	if s.AIStatePath == "" {
		return nil
	}
	b, _ := json.Marshal(s.ai)
	tmp, err := os.CreateTemp(filepath.Dir(s.AIStatePath), ".ai-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.AIStatePath)
}

// pauseAI stops all AI actions. Pausing is the safe direction, so it
// happens even if the audit log cannot be written. Caller holds s.mu.
func (s *Server) pauseAI(by, reason string) {
	if s.ai.Paused {
		return
	}
	s.ai = AIState{Paused: true, Reason: reason, Since: time.Now().UTC(), By: by}
	if err := s.Audit.Write(by, "ai_pause", map[string]any{"reason": reason}, "ok"); err != nil {
		log.Printf("AUDIT WRITE FAILED for ai_pause: %v", err)
	}
	if err := s.saveAIState(); err != nil {
		log.Printf("save ai state: %v", err)
	}
	s.metrics.Inc("nethergate_enforcer_ai_pauses_total", "by", by)
	log.Printf("AI actions PAUSED by %s: %s", by, reason)
}

// resumeAI is the risky direction: refused unless audited. Caller holds s.mu.
func (s *Server) resumeAI(reason string) error {
	if !s.ai.Paused {
		return nil
	}
	if err := s.Audit.Write("human", "ai_resume", map[string]any{"reason": reason, "was": s.ai}, "ok"); err != nil {
		return errors.New("audit log unavailable; refusing to resume the AI")
	}
	s.ai = AIState{}
	s.aiRejects = nil
	if err := s.saveAIState(); err != nil {
		return err
	}
	log.Printf("AI actions resumed by a human: %s", reason)
	return nil
}

// noteAIRejection counts refused AI actions; too many in the window means
// the AI is confused or being steered, so it is quarantined.
func (s *Server) noteAIRejection(why string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.Thresholds.AI
	now := time.Now()
	cut := now.Add(-g.QuarantineWindow.D())
	kept := s.aiRejects[:0]
	for _, t := range s.aiRejects {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	s.aiRejects = append(kept, now)
	if len(s.aiRejects) >= g.QuarantineRejections {
		s.pauseAI("quarantine", fmt.Sprintf("%d refused AI actions within %s (last: %s); possible prompt injection",
			len(s.aiRejects), g.QuarantineWindow.D(), why))
	}
}
