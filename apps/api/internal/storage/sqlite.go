package storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/agntid/observatory/api/internal/domain"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

var ErrNotFound = errors.New("not found")

type assessmentRow struct {
	ID              string    `gorm:"primaryKey;size:36"`
	Mode            string    `gorm:"index;size:16"`
	Status          string    `gorm:"index;size:24"`
	TargetURL       string    `gorm:"index"`
	CreatedAt       time.Time `gorm:"index"`
	UpdatedAt       time.Time
	CancelRequested bool
	Data            []byte
}

type eventRow struct {
	ID           uint64 `gorm:"primaryKey;autoIncrement"`
	AssessmentID string `gorm:"index;size:36"`
	Type         string `gorm:"size:32"`
	Data         []byte
	CreatedAt    time.Time `gorm:"index"`
}

type credentialRow struct {
	AssessmentID string `gorm:"primaryKey;size:64"`
	Ciphertext   []byte
	UpdatedAt    time.Time
}

type Store struct {
	db   *gorm.DB
	aead cipher.AEAD
}

func Open(path, keyPath, keyValue string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	db, err := gorm.Open(sqlite.Open(path+"?_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(&assessmentRow{}, &eventRow{}, &credentialRow{}); err != nil {
		return nil, err
	}
	key, err := loadKey(keyPath, keyValue)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, aead: aead}, nil
}

func loadKey(path, value string) ([]byte, error) {
	if value != "" {
		sum := sha256.Sum256([]byte(value))
		return sum[:], nil
	}
	if b, err := os.ReadFile(path); err == nil && len(b) == 32 {
		return b, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

func encodeAssessment(a *domain.Assessment) ([]byte, error) { return json.Marshal(a) }

func (s *Store) Create(ctx context.Context, a *domain.Assessment) error {
	b, err := encodeAssessment(a)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Create(&assessmentRow{ID: a.ID, Mode: a.Mode, Status: string(a.Status), TargetURL: a.Target.URL, CreatedAt: a.CreatedAt, Data: b}).Error
}

func (s *Store) Save(ctx context.Context, a *domain.Assessment) error {
	b, err := encodeAssessment(a)
	if err != nil {
		return err
	}
	r := s.db.WithContext(ctx).Model(&assessmentRow{}).Where("id = ?", a.ID).Updates(map[string]any{"mode": a.Mode, "status": string(a.Status), "target_url": a.Target.URL, "data": b, "updated_at": time.Now().UTC()})
	if r.Error != nil {
		return r.Error
	}
	if r.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Get(ctx context.Context, id string) (*domain.Assessment, error) {
	var row assessmentRow
	if err := s.db.WithContext(ctx).First(&row, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var a domain.Assessment
	if err := json.Unmarshal(row.Data, &a); err != nil {
		return nil, err
	}
	a.Normalize()
	return &a, nil
}

func (s *Store) List(ctx context.Context, limit int, cursor string) ([]domain.AssessmentSummary, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	q := s.db.WithContext(ctx).Order("created_at desc").Limit(limit)
	if cursor != "" {
		q = q.Where("created_at < ?", cursor)
	}
	var rows []assessmentRow
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.AssessmentSummary, 0, len(rows))
	for _, r := range rows {
		var a domain.Assessment
		if json.Unmarshal(r.Data, &a) == nil {
			a.Normalize()
			out = append(out, a.Summary())
		}
	}
	return out, nil
}

func (s *Store) ClaimNext(ctx context.Context) (*domain.Assessment, error) {
	var row assessmentRow
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("status = ?", string(domain.StatusQueued)).Order("created_at asc").First(&row).Error; err != nil {
			return err
		}
		var a domain.Assessment
		if err := json.Unmarshal(row.Data, &a); err != nil {
			return err
		}
		now := time.Now().UTC()
		a.Status = domain.StatusRunning
		a.StartedAt = &now
		a.CurrentStage = "queue"
		a.Progress = 1
		b, _ := json.Marshal(&a)
		return tx.Model(&row).Updates(map[string]any{"status": string(domain.StatusRunning), "data": b, "updated_at": now}).Error
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var a domain.Assessment
	if err := json.Unmarshal(row.Data, &a); err != nil {
		return nil, err
	}
	a.Normalize()
	now := time.Now().UTC()
	a.Status = domain.StatusRunning
	a.StartedAt = &now
	a.Progress = 1
	return &a, nil
}

func (s *Store) RequestCancel(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Model(&assessmentRow{}).Where("id = ?", id).Update("cancel_requested", true).Error
}
func (s *Store) CancelRequested(ctx context.Context, id string) (bool, error) {
	var row assessmentRow
	if err := s.db.WithContext(ctx).Select("cancel_requested").First(&row, "id = ?", id).Error; err != nil {
		return false, err
	}
	return row.CancelRequested, nil
}

func (s *Store) Append(ctx context.Context, assessmentID, eventType string, data any) (domain.Event, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return domain.Event{}, err
	}
	row := eventRow{AssessmentID: assessmentID, Type: eventType, Data: b, CreatedAt: time.Now().UTC()}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return domain.Event{}, err
	}
	return domain.Event{ID: row.ID, AssessmentID: assessmentID, Type: eventType, Data: b, CreatedAt: row.CreatedAt}, nil
}
func (s *Store) ListAfter(ctx context.Context, assessmentID string, after uint64) ([]domain.Event, error) {
	var rows []eventRow
	if err := s.db.WithContext(ctx).Where("assessment_id = ? AND id > ?", assessmentID, after).Order("id asc").Limit(250).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.Event, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.Event{ID: r.ID, AssessmentID: r.AssessmentID, Type: r.Type, Data: r.Data, CreatedAt: r.CreatedAt})
	}
	return out, nil
}

func (s *Store) Put(ctx context.Context, id string, values map[string]string) error {
	plain, err := json.Marshal(values)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	sealed := s.aead.Seal(nonce, nonce, plain, []byte(id))
	return s.db.WithContext(ctx).Save(&credentialRow{AssessmentID: id, Ciphertext: sealed, UpdatedAt: time.Now().UTC()}).Error
}
func (s *Store) GetCredentials(ctx context.Context, id string) (map[string]string, error) {
	var row credentialRow
	if err := s.db.WithContext(ctx).First(&row, "assessment_id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	n := s.aead.NonceSize()
	if len(row.Ciphertext) < n {
		return nil, fmt.Errorf("credential envelope invalid")
	}
	plain, err := s.aead.Open(nil, row.Ciphertext[:n], row.Ciphertext[n:], []byte(id))
	if err != nil {
		return nil, err
	}
	var out map[string]string
	err = json.Unmarshal(plain, &out)
	return out, err
}
func (s *Store) Delete(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&credentialRow{}, "assessment_id = ?", id).Error
}

// DeleteCredentialPrefix removes short-lived envelopes whose owning in-memory
// workflow cannot be resumed after a process restart.
func (s *Store) DeleteCredentialPrefix(ctx context.Context, prefix string) error {
	return s.db.WithContext(ctx).Where("assessment_id LIKE ?", prefix+"%").Delete(&credentialRow{}).Error
}

// Vault adapts Store's explicit credential method to avoid colliding with assessment Get.
type Vault struct{ Store *Store }

func (v Vault) Put(ctx context.Context, id string, values map[string]string) error {
	return v.Store.Put(ctx, id, values)
}
func (v Vault) Get(ctx context.Context, id string) (map[string]string, error) {
	return v.Store.GetCredentials(ctx, id)
}
func (v Vault) Delete(ctx context.Context, id string) error { return v.Store.Delete(ctx, id) }
