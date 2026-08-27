package store

import "testing"

func TestContainsWordRequiresAnIdentifierBoundary(t *testing.T) {
	words := []string{"secret", "password", "apikey"}
	for _, path := range []string{
		"SECRET_KEY", "JWT_SECRET_KEY_V2", "secretKey", "APISecret", "email_password_status",
		"apiKey", "service.apikey",
	} {
		if !containsWord(path, words) {
			t.Errorf("%q does not contain a credential word", path)
		}
	}
	for _, path := range []string{
		"ideographicsecretcircle", "passwordless", "monkey", "publicApiKeyboard",
	} {
		if containsWord(path, words) {
			t.Errorf("%q contains letters from a credential word, but not the word", path)
		}
	}
}

func TestMeaningfulSecretRejectsStatusValues(t *testing.T) {
	for _, value := range []string{"success", "FAILED", " pending "} {
		if meaningfulSecret(value) {
			t.Errorf("%q is a status, not a credential", value)
		}
	}
	for _, value := range []string{"s3cr3t-dev-key", "am0r3C0mpl3xK3y", "F12Zr47j yX@H!jmM"} {
		if !meaningfulSecret(value) {
			t.Errorf("%q is capable of serving as a credential", value)
		}
	}
}
