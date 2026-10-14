package playbook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Lesson is a human judgement that nethergate and the AI must remember:
// an answer to a review the AI asked for, or a correction of a decision
// that turned out wrong (a false block, or an attack that was missed).
//
// Lessons live next to the approved playbook and are writable by people
// only, so the AI cannot invent "lessons" that whitelist an attacker.
type Lesson struct {
	ID            string    `json:"id"`
	Time          time.Time `json:"time"`
	By            string    `json:"by"`
	IP            string    `json:"ip"`
	Verdict       string    `json:"verdict"` // "malicious" | "benign"
	Kind          string    `json:"kind"`    // "review_answer" | "correction"
	Note          string    `json:"note"`    // the human's explanation: the actual lesson
	PriorAction   string    `json:"prior_action,omitempty"`
	RulesInvolved []string  `json:"rules_involved,omitempty"` // playbook rules that matched this IP
	RulesCreated  []string  `json:"rules_created,omitempty"`
	RulesRemoved  []string  `json:"rules_removed,omitempty"`
	ReviewID      string    `json:"review_id,omitempty"`
	Question      string    `json:"ai_question,omitempty"`
}

// Review is a case the AI could not decide confidently. It did not block;
// it asks a human, and the answer becomes a Lesson.
type Review struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	IP         string    `json:"ip"`
	Score      int       `json:"score"`
	Question   string    `json:"question"`
	Considered string    `json:"considered"` // evidence for and against
	Leaning    string    `json:"leaning"`    // "malicious" | "benign" | "unsure"
	Interim    string    `json:"interim_action"`
}

const (
	MaxLessons = 2000
	MaxReviews = 200
)

// LoadList reads a JSON array file; a missing file is empty.
func LoadList[T any](path string) ([]T, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []T
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

// UpdateList edits a JSON array file under an exclusive lock and saves it
// atomically.
func UpdateList[T any](path string, mode os.FileMode, fn func([]T) ([]T, error)) error {
	lf, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o660)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
	list, err := LoadList[T](path)
	if err != nil {
		return fmt.Errorf("refusing to modify %s until it loads cleanly: %w", path, err)
	}
	if list, err = fn(list); err != nil {
		return err
	}
	if list == nil {
		list = []T{}
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(b, '\n'), mode)
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nethergate-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// LessonsFor returns the lessons about ip, newest first.
func LessonsFor(lessons []Lesson, ip string) []Lesson {
	var out []Lesson
	for i := len(lessons) - 1; i >= 0; i-- {
		if lessons[i].IP == ip {
			out = append(out, lessons[i])
		}
	}
	return out
}
