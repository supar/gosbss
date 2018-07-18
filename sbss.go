package gosbss

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/google/go-querystring/query"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
)

// ApiKeyData is struct to authenticate by login
// in the header and cookie as a key
//
// Is alternative to the classic login action
type ApiKeyData struct {
	Login  string
	Cookie *http.Cookie
}

// AuthResponse represents default response from
// the CRM server
type AuthResponse struct {
	Success   bool   `json:"success"`
	Authorize bool   `json:"authorized"`
	Login     string `json:"login"`
	Challenge int64  `json:"challenge"`
	Cname     string `json:"cname"`
}

// AuthRequest represents form encoded request to
// authenticate user
type AuthRequest struct {
	Async     uint   `url:"async"`
	Authorize string `url:"authorize"`
	Login     string `url:"login"`
	Password  string `url:"-"`
	Remember  uint   `url:"remember"`
}

// Client extends default http.Client with
// API key data and user agent information
type Client struct {
	*http.Client
	ApiKey    *ApiKeyData
	UserAgent string
}

// NewClient returns a new Client
// with defined cookie jar and user agent name
func NewClient() (c *Client) {
	var (
		cookie *cookiejar.Jar
	)

	cookie, _ = cookiejar.New(nil)

	c = &Client{
		Client: &http.Client{
			Jar: cookie,
		},
		UserAgent: "Sbss-Client",
	}

	return
}

// Login is default authentication algorithm, retrieves challenge sign
// from CRM response and send back authentication by login and password
func (c *Client) Login(urlStr string, auth *AuthRequest) (err error) {
	var (
		res    *http.Response
		result *AuthResponse
	)

	if res, err = c.authRequest(urlStr, auth); err != nil {
		return err
	}

	result = &AuthResponse{}
	if err = ReadResponse(res, &result); err != nil {
		return err
	}

	// Connection is authorized
	if result.Success {
		return nil
	}

	// Otherwise send authentication
	// Create login with challenge
	auth.Authorize = authKey(auth, result.Challenge)
	if res, err = c.authRequest(urlStr, auth); err != nil {
		return err
	}
	auth.Authorize = auth.Login

	result = &AuthResponse{}
	if err = ReadResponse(res, &result); err != nil {
		return err
	}

	if !result.Success {
		err = errors.New("Not authorized")
	}

	return
}

// SetApiKey returns ApiKeyData given login, cookie name and cookie value
func (c *Client) SetApiKey(login, cookieName, key string) {
	c.ApiKey = &ApiKeyData{
		Login: login,
		Cookie: &http.Cookie{
			Name:  cookieName,
			Value: key,
		},
	}
}

// Check if authorized
func (c *Client) authRequest(urlStr string, auth *AuthRequest) (res *http.Response, err error) {
	var (
		data *bytes.Buffer
		req  *http.Request
	)

	if auth == nil {
		return nil, errors.New("Authentication data required (login/password)")
	}

	if data, err = EncodeForm(auth); err != nil {
		return nil, err
	}

	// Prepare request just with login field
	// to check if connection is authorized
	// otherwise server will return challenge to authenticate
	if req, err = c.NewRequest("POST", urlStr, data); err != nil {
		return nil, err
	}

	// Send request
	if res, err = c.Do(req); err != nil {
		return nil, err
	}

	return
}

// NewRequest returns a new Request given a method, URL, and optional body
//
// NewRequest extends default http.NewRequest method with defined User-Agent and
// X-Requested-With headers
//
// If there is defined ApiKeyData than it will be added authentication headers
//
// CRM has recieve x-www-form-urlencoded data by POST method, so if method POST header
// Content-Type will be added
func (c *Client) NewRequest(method, urlStr string, body io.Reader) (r *http.Request, err error) {
	if r, err = http.NewRequest(method, urlStr, body); err != nil {
		return
	}

	r.Header.Set("User-Agent", c.UserAgent)
	r.Header.Set("X-Requested-With", "XMLHttpRequest")

	if c.ApiKey != nil {
		r.Header.Set("X-Sbss-Auth", c.ApiKey.Login)
		r.AddCookie(c.ApiKey.Cookie)
	}

	if method == "POST" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	return
}

// NewAuthRequest returns AuthRequest given login and password
func NewAuthRequest(login, password string) *AuthRequest {
	return &AuthRequest{
		Async:     1,
		Authorize: login,
		Login:     login,
		Password:  password,
		Remember:  0,
	}
}

// EncodeForm
func EncodeForm(data interface{}) (buf *bytes.Buffer, err error) {
	var (
		v url.Values
	)

	if v, err = query.Values(data); err != nil {
		return nil, err
	}

	return bytes.NewBufferString(v.Encode()), nil
}

// Read response body to remove every leading symbol
// unless fist right tocken will be found
//
// Decode JSON response
func ReadResponse(r *http.Response, target interface{}) (err error) {
	var (
		buf    = bufio.NewReader(r.Body)
		tokens = []byte("{}[]")
	)

	defer r.Body.Close()

	// remove leading character unless right tocken will be found
	for {
		if r, _ := buf.Peek(1); !bytes.Contains(tokens, r) {
			buf.Read(r)

			continue
		}

		break
	}

	return json.NewDecoder(buf).Decode(&target)
}

// Create authentication signature
func authKey(auth *AuthRequest, ch int64) string {
	var (
		m5 = md5.New()
		s1 = sha1.New()
	)

	io.WriteString(m5, auth.Password)

	io.WriteString(s1, auth.Login)
	io.WriteString(s1, hex.EncodeToString(m5.Sum(nil)))
	io.WriteString(s1, strconv.FormatInt(ch, 10))

	return hex.EncodeToString(s1.Sum(nil))
}
