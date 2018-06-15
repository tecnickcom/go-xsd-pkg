package xsdt

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestDateTime(t *testing.T) {
	t1 := time.Now()
	var d DateTime
	d.SetTime(t1)
	t2, err := d.GetTime()
	assert.Nil(t, err)
	assert.Equal(t, t1.UTC(), t2.UTC())
}

func TestDateTime_RFC3339(t *testing.T) {
	t1 := time.Now().Truncate(time.Second)
	var d DateTime
	d.Set(t1.Format(time.RFC3339))
	t2, err := d.GetTime()
	assert.Nil(t, err)
	assert.Equal(t, t1.UTC(), t2.UTC())
}

func TestDateTime_RFC3339Nano(t *testing.T) {
	t1 := time.Now()
	var d DateTime
	d.Set(t1.Format(time.RFC3339Nano))
	t2, err := d.GetTime()
	assert.Nil(t, err)
	assert.Equal(t, t1.UTC(), t2.UTC())
}

func TestDateTime_NoZ(t *testing.T) {
	t1 := time.Now().UTC()
	var d DateTime
	d.Set(t1.Format("2006-01-02T15:04:05.999999999"))
	t2, err := d.GetTime()
	assert.Nil(t, err)
	assert.Equal(t, t1.UTC(), t2.UTC())
}
