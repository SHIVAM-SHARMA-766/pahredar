package auth

import "testing"

func TestHashVerifyRoundtrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := VerifyPassword(hash, "correct horse battery staple"); err != nil {
		t.Fatalf("verify correct password: %v", err)
	}
	if err := VerifyPassword(hash, "wrong password"); err != ErrMismatch {
		t.Fatalf("verify wrong password: want ErrMismatch, got %v", err)
	}
}

func TestHashIsSalted(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Fatal("two hashes of the same password are identical; salt is not random")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "notahash", "$argon2id$bad", "$argon2i$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA"} {
		if err := VerifyPassword(bad, "x"); err == nil {
			t.Fatalf("expected error for malformed hash %q", bad)
		}
	}
}

func TestEmptyPasswordRejected(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Fatal("expected error hashing empty password")
	}
}
