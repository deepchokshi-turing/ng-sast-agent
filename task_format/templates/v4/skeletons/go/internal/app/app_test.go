package app

import "testing"

func TestHandle(t *testing.T) {
	if Handle("hello")["answer"] == "" {
		t.Fatal("empty answer")
	}
}
