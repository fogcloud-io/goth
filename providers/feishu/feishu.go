package feishu

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

var (
	AuthURL     = "https://open.feishu.cn/open-apis/authen/v1/index"
	TokenURL    = "https://open.feishu.cn/open-apis/authen/v1/access_token"
	AppTokenURL = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal"
	ProfileURL  = "https://open.feishu.cn/open-apis/authen/v1/user_info"
)

var UrlPath = ""

var ErrUserId = errors.New("userId not exist")
var ErrNoAccess = errors.New("no access")

// New creates a new feishu provider, and sets up important connection details.
// You should always call `feishu.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	return NewCustomisedURL(clientKey, secret, callbackURL, AuthURL, TokenURL, AppTokenURL, ProfileURL, scopes...)
}

// NewCustomisedURL is similar to New(...) but can be used to set custom URLs to connect to
func NewCustomisedURL(clientKey, secret, callbackURL, authURL, tokenURL, AppTokenURL, ProfileURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "feishu",
		profileURL:   ProfileURL,
		TokenURL:     tokenURL,
		AppTokenURL:  AppTokenURL,
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing feishu.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	TokenURL     string
	AppTokenURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	profileURL   string
	// token caches the access_token
	token *oauth2.Token
}

type AppAccessToken struct {
	AppAccessToken    string `json:"app_access_token"`
	Code              int    `json:"code"`
	TenantAccessToken string `json:"tenant_access_token"`
}

type UserToken struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type UserInfo struct {
	Name      string `json:"name"`
	EnName    string `json:"en_name"`
	AvatarUrl string `json:"avatar_url"`
	UserId    string `json:"user_id"`
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the feishu package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks feishu for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	params := url.Values{}
	params.Add("app_id", p.ClientKey)
	params.Add("state", state)
	params.Add("redirect_uri", p.CallbackURL)

	authUrl := p.config.Endpoint.AuthURL
	url := fmt.Sprintf("%s?%s", authUrl, params.Encode())
	UrlPath = url
	session := &Session{
		AuthURL: url,
	}

	return session, nil
}

// FetchUser will go to feishu and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken: sess.AccessToken,
		Provider:    p.Name(),
	}

	if user.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	request, err := http.NewRequest("GET", p.profileURL, nil)
	if err != nil {
		return user, err
	}
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", sess.AccessToken))
	response, err := p.Client().Do(request)

	if err != nil {
		return user, err
	}

	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("GitHub API responded with a %d trying to fetch user information", response.StatusCode)
	}

	bits, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	err = userFromReader(bits, &user)
	if err != nil {
		return user, err
	}
	return user, err
}

func userFromReader(bytes []byte, user *goth.User) error {
	userInfo := struct {
		Code int      `json:"code"`
		Msg  string   `json:"msg"`
		Data UserInfo `json:"data"`
	}{}

	err := json.Unmarshal(bytes, &userInfo)
	if err != nil {
		return err
	}

	user.Name = userInfo.Data.Name
	user.NickName = userInfo.Data.Name
	user.AvatarURL = userInfo.Data.AvatarUrl
	user.UserID = userInfo.Data.UserId

	return err
}

func newConfig(provider *Provider, authURL, tokenURL string, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	for _, scope := range scopes {
		c.Scopes = append(c.Scopes, scope)
	}

	return c
}

//RefreshToken refresh token is not provided by feishu
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by feishu")
}

//RefreshTokenAvailable refresh token is not provided by feishu
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

func (p *Provider) fetchToken(code string) (*oauth2.Token, error) {
	if p.token != nil && p.token.Valid() {
		return p.token, nil
	}

	appToken, err := p.fetchAppToken()
	if err != nil {
		return nil, err
	}

	log.Printf("appToken:%s  code:%s", appToken, code)

	params := make(map[string]string)
	params["grant_type"] = "authorization_code"
	params["code"] = code

	b, _ := json.Marshal(params)

	request, err := http.NewRequest("POST", p.TokenURL, bytes.NewBuffer(b))
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", appToken))
	request.Header.Add("Content-Type", "application/json; charset=utf-8")

	resp, err := p.Client().Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode)
	}
	defer resp.Body.Close()

	obj := struct {
		Code int       `json:"code"`
		Msg  string    `json:"msg"`
		Data UserToken `json:"data"`
	}{}
	if err = json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return nil, err
	}
	if obj.Code != 0 {
		return nil, fmt.Errorf("CODE: %d, MSG: %s", obj.Code, obj.Msg)
	}

	p.token = &oauth2.Token{
		AccessToken:  obj.Data.AccessToken,
		RefreshToken: obj.Data.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(obj.Data.ExpiresIn) * time.Second),
	}

	return p.token, nil
}

func (p *Provider) fetchAppToken() (string, error) {

	values := make(url.Values)
	values.Set("app_id", p.ClientKey)
	values.Set("app_secret", p.Secret)

	response, err := p.Client().PostForm(p.AppTokenURL, values)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	result, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	var appToken AppAccessToken
	err = json.Unmarshal(result, &appToken)
	if err != nil {
		log.Printf("get apptoken failed result:%s err:%s", string(result), err)
		return "", err
	}

	return appToken.AppAccessToken, nil
}
