package manage

import (
	"net/url"
	"strings"

	"gopkg.in/oauth2.v3/errors"
)

type (
	// ValidateURIHandler validates that redirectURI is contained in baseURI
	ValidateURIHandler func(baseURI, redirectURI string) (err error)
)

// DefaultValidateURI validates that redirectURI is contained in baseURI
func DefaultValidateURI(baseURI string, redirectURI string) (err error) {
	base, err := url.Parse(baseURI)
	if err != nil {
		return
	}
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		return
	}
	if !strings.HasSuffix(redirect.Host, base.Host) {
		err = errors.ErrInvalidRedirectURI
	}
	return
}

type (
	// MatchClientSecretHandler checks the equality of givenSecret and storedSecret
	MatchClientSecretHandler func(givenSecret, storedSecret string) (isValid bool)
)

// DefaultMatchClientSecretHandler validates that givenSecret is the same as storedSecret
func DefaultMatchClientSecretHandler(givenSecret, storedSecret string) (isValid bool) {
	if givenSecret == storedSecret {
		isValid = true
		return
	}
	return
}
