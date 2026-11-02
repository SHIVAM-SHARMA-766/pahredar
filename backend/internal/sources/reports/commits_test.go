package reports

import (
	"slices"
	"testing"
)

func TestCommitURLs(t *testing.T) {
	got := CommitURLs([]string{
		"https://github.com/apache/activemq/commit/3eaf3107f4fb9a3ce7ab45c175bfaeac7e866d5b",
		"https://github.com/apache/activemq/commit/3EAF3107F4FB9A3CE7AB45C175BFAEAC7E866D5B",
		"https://github.com/o/r/pull/12/commits/abc1234",
		"https://github.com/o/r/issues/1",
		"https://gitlab.com/o/r/-/commit/abcdef1",
	})
	want := []string{
		"https://github.com/apache/activemq/commit/3eaf3107f4fb9a3ce7ab45c175bfaeac7e866d5b",
		"https://github.com/o/r/pull/12/commits/abc1234",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
