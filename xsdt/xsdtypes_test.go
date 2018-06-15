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
