package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestCredentialVaultRoundTripAndDelete(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "test.db"), filepath.Join(dir, "key"), "")
	if err != nil {
		t.Fatal(err)
	}
	vault := Vault{Store: store}
	ctx := context.Background()
	want := map[string]string{"bearer": "super-secret", "header:X-Tenant": "acme"}
	if err := vault.Put(ctx, "assessment-1", want); err != nil {
		t.Fatal(err)
	}
	got, err := vault.Get(ctx, "assessment-1")
	if err != nil {
		t.Fatal(err)
	}
	if got["bearer"] != want["bearer"] {
		t.Fatal("credential mismatch")
	}
	if err := vault.Delete(ctx, "assessment-1"); err != nil {
		t.Fatal(err)
	}
	got, err = vault.Get(ctx, "assessment-1")
	if err != nil || len(got) != 0 {
		t.Fatal("credentials were not deleted")
	}
}

func TestDeleteCredentialPrefixRemovesOnlyOAuthEnvelopes(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "test.db"), filepath.Join(dir, "key"), "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for id, token := range map[string]string{"oauth-session-1": "oauth-token", "assessment-1": "assessment-token"} {
		if err := store.Put(ctx, id, map[string]string{"access_token": token}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.DeleteCredentialPrefix(ctx, "oauth-"); err != nil {
		t.Fatal(err)
	}
	oauthValues, err := store.GetCredentials(ctx, "oauth-session-1")
	if err != nil || len(oauthValues) != 0 {
		t.Fatal("OAuth credential envelope was not removed")
	}
	assessmentValues, err := store.GetCredentials(ctx, "assessment-1")
	if err != nil || assessmentValues["access_token"] != "assessment-token" {
		t.Fatal("assessment credential envelope was removed")
	}
}
