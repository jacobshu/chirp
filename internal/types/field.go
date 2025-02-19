package types

import (
	"time"

	"github.com/google/uuid"
)

type Field struct {
	ID        uuid.UUID
	CreatedAt time.Time
	UpdatedAt time.Time
	Content   string
	SiteID    uuid.UUID
}
