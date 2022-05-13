package dingtalk

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/markbates/goth"
	"strings"
)

// Session stores data during the auth process with Github.
type Session struct {
	AuthURL     string
	AccessToken string
	UserID      string
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Github provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with Github and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.fetchToken()
	if err != nil {
		return "", err
	}
	s.AccessToken = token.AccessToken

	userID, err := p.fetchUserID(s, params.Get("code"))
	if err != nil {
		return "", err
	}
	s.UserID = userID
	fmt.Printf("userID:%s", userID)
	return token.AccessToken, err
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}
