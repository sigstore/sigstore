package utils

import (
	"testing"
)

func TestFindString(t *testing.T) {
	result := FindString("text/plain; charset=utf-8")
	if  !result {
		t.Error("FindString failed\n")
	}
}

