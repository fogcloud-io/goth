package dingtalk

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

var (
	AuthURL = "https://oapi.dingtalk.com/connect/qrconnect"
	//AuthURL    = "https://oapi.dingtalk.com/connect/oauth2/sns_authorize"
	//TokenURL   = "https://api.dingtalk.com/v1.0/oauth2/userAccessToken"
	TokenURL   = "https://oapi.dingtalk.com/gettoken"
	UserIdURL  = "https://oapi.dingtalk.com/topapi/user/getbyunionid"
	ProfileURL = "https://oapi.dingtalk.com/topapi/v2/user/get"
	unionURL   = "https://oapi.dingtalk.com/sns/getuserinfo_bycode"
)

var UrlPath string = ""

var ErrUserId = errors.New("userId not exist")
var ErrNoAccess = errors.New("no access")

// New creates a new dingtalk provider, and sets up important connection details.
// You should always call `dingtalk.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL, agentId string, scopes ...string) *Provider {
	return NewCustomisedURL(clientKey, secret, callbackURL, AuthURL, TokenURL, UserIdURL, ProfileURL, unionURL, agentId, scopes...)
}

// NewCustomisedURL is similar to New(...) but can be used to set custom URLs to connect to
func NewCustomisedURL(clientKey, secret, callbackURL, authURL, tokenURL, userIdURL, ProfileURL, unionURL, AgentId string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "dingtalk",
		userIdURL:    userIdURL,
		profileURL:   ProfileURL,
		unionURL:     unionURL,
		TokenURL:     tokenURL,
		AgentId:      AgentId,
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing dingtalk.
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	TokenURL     string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
	userIdURL    string
	profileURL   string
	unionURL     string
	// token caches the access_token
	token   *oauth2.Token
	AgentId string
}

type UserIdResult struct {
	Errcode  int              `json:"errcode"`
	Errmsg   string           `json:"errmsg"`
	UserInfo DingTalkUserInfo `json:"user_info"`
}

type DingTalkUserInfo struct {
	Nick                 string `json:"nick"`
	Unionid              string `json:"unionid"`
	Openid               string `json:"openid"`
	MainOrgAuthHighLevel bool   `json:"main_org_auth_high_level"`
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

// Debug is a no-op for the dingtalk package.
func (p *Provider) Debug(debug bool) {}

// BeginAuth asks dingtalk for an authentication end-point.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	params := url.Values{}
	params.Add("appid", p.ClientKey)
	params.Add("response_type", "code")
	params.Add("state", state)
	params.Add("scope", "snsapi_login")
	params.Add("redirect_uri", p.CallbackURL)

	authUrl := p.config.Endpoint.AuthURL
	url := fmt.Sprintf("%s?%s", authUrl, params.Encode())
	fmt.Printf("url==>:%s", url)
	UrlPath = url
	session := &Session{
		AuthURL: url,
	}
	return session, nil
}

// FetchUser will go to dingtalk and access basic information about the user.
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

	m := map[string]string{"userid": sess.UserID}
	m["language"] = "zh_CN"
	res, err := json.Marshal(m)
	if err != nil {
		fmt.Println(res)
		return user, err
	}
	fmt.Println(string(res))

	url := fmt.Sprintf("%s?access_token=%s", p.profileURL, sess.AccessToken)

	response, err := p.Client().Post(url, "application/json", bytes.NewBuffer(res))
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

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return user, err
	}
	fmt.Printf("result:%+v", user.RawData)
	err = userFromReader(bytes.NewReader(bits), &user)
	if err != nil {
		return user, err
	}
	fmt.Printf("result:%+v", user.RawData)
	return user, err
}

func userFromReader(reader io.Reader, user *goth.User) error {
	r := struct {
		Errcode int    `json:"errcode"`
		Errmsg  string `json:"errmsg"`
		Result  struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Avatar string `json:"avatar"`
			Userid string `json:"userid"`
		}
	}{}

	err := json.NewDecoder(reader).Decode(&r)
	if err != nil {
		return err
	}

	if r.Errcode == 50002 {
		return ErrNoAccess
	}

	user.Name = r.Result.Name
	user.NickName = r.Result.Name
	user.AvatarURL = r.Result.Avatar
	user.UserID = r.Result.Userid

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

//RefreshToken refresh token is not provided by dingtalk
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, errors.New("Refresh token is not provided by dingtalk")
}

//RefreshTokenAvailable refresh token is not provided by dingtalk
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}

func (p *Provider) fetchToken() (*oauth2.Token, error) {
	if p.token != nil && p.token.Valid() {
		return p.token, nil
	}

	params := url.Values{}
	params.Add("appkey", p.ClientKey)
	params.Add("appsecret", p.Secret)

	resp, err := p.Client().Get(fmt.Sprintf("%s?%s", p.TokenURL, params.Encode()))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wecom /gettoken returns code: %d", resp.StatusCode)
	}

	obj := struct {
		AccessToken string        `json:"access_token"`
		ExpiresIn   time.Duration `json:"expires_in"`
		Code        int           `json:"errcode"`
		Msg         string        `json:"errmsg"`
	}{}
	if err = json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return nil, err
	}
	if obj.Code != 0 {
		return nil, fmt.Errorf("CODE: %d, MSG: %s", obj.Code, obj.Msg)
	}

	p.token = &oauth2.Token{
		AccessToken: obj.AccessToken,
		Expiry:      time.Now().Add(obj.ExpiresIn * time.Second),
	}

	return p.token, nil

}

func (p *Provider) fetchUserID(session goth.Session, code string) (string, error) {
	unionId, err := p.fetchUnionId(code)
	if err != nil {
		return "", err
	}
	return p.fetchUserIdByUnionId(session, unionId)
}

func (p *Provider) fetchUnionId(code string) (string, error) {
	timestamp := time.Now().UnixNano() / 1e6
	strTimeStamp := fmt.Sprintf("%d", timestamp)

	key := []byte(p.Secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(strTimeStamp))

	sha := h.Sum(nil)
	sig := base64.StdEncoding.EncodeToString(sha)
	mysig := url.QueryEscape(sig)

	m := map[string]string{"tmp_auth_code": code}
	res, err := json.Marshal(m)
	if err != nil {
		fmt.Println(res)
		return "", err
	}
	fmt.Println(string(res))

	url := fmt.Sprintf("%s?signature=%s&timestamp=%d&accessKey=%s", p.unionURL, mysig, timestamp, p.ClientKey)
	resp, err := p.Client().Post(url, "application/json", bytes.NewBuffer(res))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("dingtalk /getuserinfo returns code: %d", resp.StatusCode)
	}

	result, err := ioutil.ReadAll(resp.Body)
	var ur UserIdResult
	err = json.Unmarshal(result, &ur)
	fmt.Printf("result:%+v", ur)
	if ur.Errcode != 0 {
		return "", fmt.Errorf("CODE: %d, MSG: %s", ur.Errcode, ur.Errmsg)
	}
	return ur.UserInfo.Unionid, nil
}

func (p *Provider) fetchUserIdByUnionId(session goth.Session, unionId string) (userId string, err error) {
	var user goth.User
	sess := session.(*Session)

	if sess.AccessToken == "" {
		// data is not yet retrieved since accessToken is still empty
		return "", fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	m := map[string]string{"unionid": unionId}
	res, err := json.Marshal(m)
	if err != nil {
		fmt.Println(res)
		return "", err
	}
	fmt.Println(string(res))

	url := fmt.Sprintf("%s?access_token=%s", p.userIdURL, sess.AccessToken)
	fmt.Println(url)
	response, err := p.Client().Post(url, "application/json", bytes.NewBuffer(res))
	if err != nil {
		return "", err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API responded with a %d trying to fetch user information", response.StatusCode)
	}

	bits, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	err = json.NewDecoder(bytes.NewReader(bits)).Decode(&user.RawData)
	if err != nil {
		return "", err
	}
	return getUserId(user.RawData)
}

func getUserId(data map[string]interface{}) (userId string, err error) {
	var result map[string]interface{}
	if data["result"] != nil && data["result"] != "" {
		result = data["result"].(map[string]interface{})
		return result["userid"].(string), nil
	}
	return "", ErrUserId
}
