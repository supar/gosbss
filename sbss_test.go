package gosbss

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

const UserAgent = "Sbss-Client"

func NewTestServer(handler http.Handler) (ts *httptest.Server) {
	ts = httptest.NewServer(handler)
	return
}

func Test_LoginAuthStruct(t *testing.T) {
	var (
		a = []struct {
			login, password string
			result          []byte
		}{
			{
				login:    "user1",
				password: "password1",
				result:   []byte("async=1&authorize=user1&login=user1&remember=0"),
			},
		}

		b *AuthRequest
	)

	for i, v := range a {
		b = NewAuthRequest(v.login, v.password)

		if r, err := EncodeForm(b); err != nil {
			t.Errorf("Unexpected error %s", err.Error())
		} else {
			if !bytes.Equal(r.Bytes(), v.result) {
				t.Errorf("Unexpected result at index %d", i)
			}
		}
	}
}

func Test_CheckUserAgentHeader(t *testing.T) {
	var (
		cli = NewClient()

		err error
		r   *http.Request
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := UserAgent
		if v := r.UserAgent(); v != u {
			t.Errorf("Expected User-Agent %s, but got %s", u, v)
		}
	})

	ts := NewTestServer(handler)
	defer ts.Close()

	if r, err = cli.NewRequest("GET", ts.URL, nil); err != nil {
		t.Error(err)
	}

	if _, err = cli.Do(r); err != nil {
		t.Error(err)
	}
}

func Test_ReadResponseWithInvalidLeadingCharacters(t *testing.T) {
	var (
		cli = NewClient()
		a   = []struct {
			in, out []byte
		}{
			{
				in: []byte(`({"success":true})`),
			},
			{
				in: []byte(` ( {"success":true} )`),
			},
			{
				in: []byte(`\t\n\t ( {
					"success":true}`),
			},
			{
				in: []byte(`({"success":false,"authorize":false,"login":null,"challenge":8545724,"cname":"3b47a663b0765fe1"})`),
			},
		}

		err error
		r   *http.Request
		res *http.Response
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := ioutil.ReadAll(r.Body)
		w.Write(data)
	})

	ts := NewTestServer(handler)
	defer ts.Close()

	for i, v := range a {
		if r, err = cli.NewRequest("POST", ts.URL, bytes.NewReader(v.in)); err != nil {
			t.Error(err)
			continue
		}

		if res, err = cli.Do(r); err != nil {
			t.Error(err)
			continue
		}

		target := AuthResponse{}
		if err = ReadResponse(res, &target); err != nil {
			t.Error(err)
			continue
		}

		if (i < 3 && !target.Success) || (i > 2 && target.Success) {
			t.Errorf("Unexpected value at index ", i)
		}
	}
}

func Test_AuthKeyValid(t *testing.T) {
	var (
		a = &AuthRequest{
			Login:    "user1",
			Password: "password1",
		}
		c int64 = 7374616523
		r       = "bc474ed96e52bd6de501060ece3f6f334cc42db7"
	)

	if res := authKey(a, c); res != r {
		t.Errorf("Unexpected result %s, expected %s", res, r)
	}
}

func Test_AuthenticationStatusSuccess(t *testing.T) {
	var (
		cli   = NewClient()
		lauth = NewAuthRequest("user1", "")
		r     = &AuthResponse{}

		err error
		res *http.Response
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.PostFormValue("login") == lauth.Login {
			io.WriteString(w, `({"success":true})`)

			return
		}

		io.WriteString(w, `({"success":false,"authorize":false,"login":null,"challenge":5698316,"cname":"3b47a663b0765fe1"})`)
	})

	ts := NewTestServer(handler)
	defer ts.Close()

	if res, err = cli.authRequest(ts.URL, lauth); err != nil {
		t.Error(err)
	}

	if err = ReadResponse(res, r); err != nil {
		t.Error(err)
	}

	if !r.Success {
		t.Error("Expected success:true")
	}
}

func Test_AuthenticationStatusFail(t *testing.T) {
	var (
		cli   = NewClient()
		lauth = NewAuthRequest("user1", "password1")
		r     = &AuthResponse{}

		err error
		res *http.Response
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `({"success":false,"authorize":false,"login":null,"challenge":5698316,"cname":"3b47a663b0765fe1"})`)
	})

	ts := NewTestServer(handler)
	defer ts.Close()

	if res, err = cli.authRequest(ts.URL, lauth); err != nil {
		t.Error(err)
	}

	if err = ReadResponse(res, r); err != nil {
		t.Error(err)
	}

	if r.Success {
		t.Error("Expected success:false")
	}

	if r.Challenge == 0 {
		t.Error("Expected not empty challenge")
	}
}

func Test_LoginSuccess(t *testing.T) {
	var (
		cli   = NewClient()
		lauth = NewAuthRequest("user1", "password1")
		c     = "ccebf1b64e210b61ba63b6475d5c80d4ff0b09c8"

		err error
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.PostFormValue("login") == lauth.Login && r.PostFormValue("authorize") == c {
			io.WriteString(w, `({"success": true})`)

			return
		}

		io.WriteString(w, `({"success":false,"authorize":false,"login":null,"challenge":5698316,"cname":"3b47a663b0765fe1"})`)
	})

	ts := NewTestServer(handler)
	defer ts.Close()

	if err = cli.Login(ts.URL, lauth); err != nil {
		t.Error(err)
	}

	if !cli.authorized {
		t.Error("Expected authorized:true in the struct")
	}
}

func Test_ApiKeySuccess(t *testing.T) {
	var (
		cli = NewClient()

		authRes    = &AuthResponse{}
		user       = "user1"
		cookieName = "be6657bf2d3271ef"
		key        = user + ":0:9174f402ddc2923037e23c094175a495f3cbc19d"

		r   *http.Request
		res *http.Response
		err error
	)

	cli.SetApiKey(user, cookieName, key)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := r.Header.Get("X-Sbss-Auth"); h != user {
			io.WriteString(w, `({"success":false,"authorize":false,"login":null,"challenge":5698317,"cname":"3b47a663b0765fe1"})`)
			return
		}

		if c, _ := r.Cookie(cookieName); c == nil || c.Value != key {
			io.WriteString(w, `({"success":false,"authorize":false,"login":null,"challenge":5698317,"cname":"3b47a663b0765fe1"})`)
			return
		}

		io.WriteString(w, `({"success":true})`)
	})

	ts := NewTestServer(handler)
	defer ts.Close()

	if r, err = cli.NewRequest("GET", ts.URL, nil); err != nil {
		t.Error(err)
	}

	if res, err = cli.Do(r); err != nil {
		t.Error(err)
	}

	if err = ReadResponse(res, authRes); err != nil || !authRes.Success {
		if err == nil {
			t.Error("Unauthorized")
		} else {
			t.Error(err)
		}
	}
}
