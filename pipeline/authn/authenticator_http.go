package authn

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	"github.com/tidwall/gjson"

	"github.com/ory/go-convenience/stringsx"

	"github.com/ory/herodot"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/helper"
	"github.com/ory/oathkeeper/pipeline"
)

func init() {
	gjson.AddModifier("this", func(json, arg string) string {
		return json
	})
}

type AuthenticatorHttpFilter struct {
}

type AuthenticatorHttpConfiguration struct {
	OnlyHeaders       []string          `json:"only_headers"`
	URL               string            `json:"url"`
	PreservePath      bool              `json:"preserve_path"`
	PassStatuses      []int             `json:"pass_statuses"`
	ExtraFrom         string            `json:"extra_from"`
	ExtraFromHeader   map[string]string `json:"extra_from_header"`
	SubjectFrom       string            `json:"subject_from"`
	SubjectFromHeader string            `json:"subject_from_header"`
	NonEmptySubject   bool              `json:"non_empty_subject"`
	ExtraPostProcess  string            `json:"extra_post_process"`
}

type AuthenticatorHttp struct {
	c configuration.Provider
}

func NewAuthenticatorHttp(c configuration.Provider) *AuthenticatorHttp {
	return &AuthenticatorHttp{
		c: c,
	}
}

func (a *AuthenticatorHttp) GetID() string {
	return "http"
}

func (a *AuthenticatorHttp) Validate(config json.RawMessage) error {
	if !a.c.AuthenticatorIsEnabled(a.GetID()) {
		return NewErrAuthenticatorNotEnabled(a)
	}

	_, err := a.Config(config)
	return err
}

func (a *AuthenticatorHttp) Config(config json.RawMessage) (*AuthenticatorHttpConfiguration, error) {
	var c AuthenticatorHttpConfiguration
	if err := a.c.AuthenticatorConfig(a.GetID(), config, &c); err != nil {
		return nil, NewErrAuthenticatorMisconfigured(a, err)
	}

	if len(c.SubjectFrom) > 0 && len(c.SubjectFromHeader) > 0 {
		return nil, NewErrAuthenticatorMisconfigured(a, errors.New("Can be set only one of: subject_from or subject_from_header"))
	}

	if len(c.PassStatuses) == 0 {
		c.PassStatuses = []int{http.StatusOK}
	}

	if len(c.ExtraFrom) == 0 && len(c.ExtraFromHeader) == 0 {
		c.ExtraFrom = "extra"
	}

	if len(c.SubjectFrom) == 0 && len(c.SubjectFromHeader) == 0 {
		c.SubjectFrom = "subject"
	}

	return &c, nil
}

func (a *AuthenticatorHttp) Authenticate(r *http.Request, session *AuthenticationSession, config json.RawMessage, _ pipeline.Rule) error {
	cf, err := a.Config(config)
	if err != nil {
		return err
	}

	if !httpResponsible(r, cf.OnlyHeaders) {
		return errors.WithStack(ErrAuthenticatorNotResponsible)
	}

	body, header, err := forwardRequest(r, cf.URL, cf.PreservePath, cf.PassStatuses)
	if err != nil {
		return err
	}

	var (
		subject string
		extra   = map[string]interface{}{}
	)

	if len(cf.SubjectFrom) > 0 {
		subjectRaw := []byte(gjson.GetBytes(body, cf.SubjectFrom).Raw)
		if err = json.Unmarshal(subjectRaw, &subject); err != nil {
			return helper.ErrForbidden.WithReasonf("The configured subject_from GJSON path returned an error on JSON output: %s", err.Error()).WithDebugf("GJSON path: %s\nBody: %s\nResult: %s", cf.SubjectFrom, body, subjectRaw).WithTrace(err)
		}
	} else if len(cf.SubjectFromHeader) > 0 {
		subject = header.Get(cf.SubjectFromHeader)
	}

	if len(cf.ExtraFrom) > 0 {
		extraRaw := []byte(stringsx.Coalesce(gjson.GetBytes(body, cf.ExtraFrom).Raw, "null"))
		if err = json.Unmarshal(extraRaw, &extra); err != nil {
			return helper.ErrForbidden.WithReasonf("The configured extra_from GJSON path returned an error on JSON output: %s", err.Error()).WithDebugf("GJSON path: %s\nBody: %s\nResult: %s", cf.ExtraFrom, body, extraRaw).WithTrace(err)
		}
	} else if len(cf.ExtraFromHeader) > 0 {
		extra = make(map[string]interface{}, len(cf.ExtraFromHeader))
		for k, headerName := range cf.ExtraFromHeader {
			extra[k] = header.Get(headerName)
		}
	}

	if cf.NonEmptySubject && len(subject) == 0 {
		return helper.ErrForbidden.WithReasonf("Extracted subject is empty")
	}

	switch cf.ExtraPostProcess {
	case "base64":
		d, _ := json.Marshal(extra)
		b64 := base64.StdEncoding.EncodeToString(d)
		extra["__base64"] = b64
	}

	subject = stringsx.Coalesce(subject, "null")

	session.Subject = subject
	session.Extra = extra
	return nil
}

func httpResponsible(r *http.Request, onlyHeaders []string) bool {
	if len(onlyHeaders) == 0 {
		return true
	}
	for _, header := range onlyHeaders {
		if len(r.Header.Get(header)) > 0 {
			return true
		}
	}
	return false
}

func forwardRequest(r *http.Request, rawURL string, preservePath bool, passStatuses []int) (json.RawMessage, http.Header, error) {
	reqUrl, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to parse session check URL: %s", err))
	}

	if !preservePath {
		reqUrl.Path = r.URL.Path
	}

	req := &http.Request{
		Method: r.Method,
		URL:    reqUrl,
		Header: r.Header,
	}

	if r.Body != nil {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, nil, err
		}
		if err := r.Body.Close(); err != nil {
			return nil, nil, err
		}
		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, helper.ErrForbidden.WithReason(err.Error()).WithTrace(err)
	}

	for _, passStatus := range passStatuses {
		if res.StatusCode == passStatus {

			var reader io.ReadCloser
			switch res.Header.Get("Content-Encoding") {
			case "gzip":
				defer res.Body.Close()
				reader, err = gzip.NewReader(res.Body)
				if err != nil {
					return json.RawMessage{}, nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to fetch data from remote: gzip: %+v", err))
				}
			default:
				reader = res.Body
			}

			defer reader.Close()
			body, err := ioutil.ReadAll(reader)
			if err != nil {
				return json.RawMessage{}, nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to fetch data from remote: %+v", err))
			}

			return body, res.Header, nil
		}
	}

	return json.RawMessage{}, nil, errors.WithStack(helper.ErrUnauthorized)
}
