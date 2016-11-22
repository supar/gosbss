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
	"net/url"
	"strconv"
)

type AuthResponse struct {
	Success   bool   `json:"success"`
	Authorize bool   `json:"authorized"`
	Login     string `json:"login"`
	Challenge int64  `json:"challenge"`
	Cname     string `json:"cname"`
}

type Client struct {
	*http.Client
	authorized bool
	UserAgent  string
}

type AuthRequest struct {
	Async     uint   `url:"async"`
	Authorize string `url:"authorize"`
	Login     string `url:"login"`
	Password  string `url:"-"`
	Remember  uint   `url:"remember"`
}

// Create new http client
func NewClient() (c *Client, err error) {
	c = &Client{
		Client:    &http.Client{},
		UserAgent: "Sbss-Client",
	}

	return
}

// Authenticate manager
func (this *Client) Login(urlStr string, auth *AuthRequest) (err error) {
	var (
		res    *http.Response
		result *AuthResponse
	)

	if this.authorized {
		return
	}

	if res, err = this.authRequest(urlStr, auth); err != nil {
		return err
	}

	result = &AuthResponse{}
	if err = ReadResponse(res, &result); err != nil {
		return err
	}

	// Connection is authorized
	if result.Success {
		this.authorized = true
		return nil
	}

	// Otherwise send authentication
	// Create login with challenge
	auth.Authorize = authKey(auth, result.Challenge)
	if res, err = this.authRequest(urlStr, auth); err != nil {
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

	this.authorized = true
	return
}

// Check if auithorized
func (this *Client) authRequest(urlStr string, auth *AuthRequest) (res *http.Response, err error) {
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
	if req, err = this.NewRequest("POST", urlStr, data); err != nil {
		return nil, err
	}

	// Send request
	if res, err = this.Do(req); err != nil {
		return nil, err
	}

	return
}

// Override NewRequest to add User_agent header
func (this *Client) NewRequest(method, urlStr string, body io.Reader) (r *http.Request, err error) {
	if r, err = http.NewRequest(method, urlStr, body); err != nil {
		return
	}

	r.Header.Set("User-Agent", this.UserAgent)
	r.Header.Set("X-Requested-With", "XMLHttpRequest")

	if method == "POST" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	return
}

func NewAuthRequest(login, password string) *AuthRequest {
	return &AuthRequest{
		Async:     1,
		Authorize: login,
		Login:     login,
		Password:  password,
		Remember:  0,
	}
}

// Encode struct to the form-data
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

	io.WriteString(m5, auth.Login)
	io.WriteString(m5, auth.Password)

	io.WriteString(s1, hex.EncodeToString(m5.Sum(nil)))
	io.WriteString(s1, strconv.FormatInt(ch, 10))

	return hex.EncodeToString(s1.Sum(nil))
}
