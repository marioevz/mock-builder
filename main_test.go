package main

import (
	"testing"
)

func TestLogger(t *testing.T) {
	logger.Logf("logf should not panic")
}
