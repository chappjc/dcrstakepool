package system

import (
	"crypto/sha256"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/btcsuite/btclog"
	"github.com/decred/dcrstakepool/models"
	"github.com/gorilla/sessions"
	"github.com/pelletier/go-toml"
	"github.com/zenazn/goji/web"
	"gopkg.in/gorp.v1"
)

type CsrfProtection struct {
	Key    string
	Cookie string
	Header string
	Secure bool
}

type Application struct {
	Config         *toml.TomlTree
	Template       *template.Template
	Store          *sessions.CookieStore
	DbMap          *gorp.DbMap
	CsrfProtection *CsrfProtection
	Logger         btclog.Logger
}

func NewApplication(filename *string, logger btclog.Logger) *Application {
	app := &Application{Logger: logger}

	app.Init(filename)

	return app
}

func (application *Application) Init(filename *string) {

	config, err := toml.LoadFile(*filename)
	if err != nil {
		application.Logger.Critical("TOML load failed: %s\n", err)
		os.Exit(1)
	}

	hash := sha256.New()
	io.WriteString(hash, config.Get("cookie.mac_secret").(string))
	application.Store = sessions.NewCookieStore(hash.Sum(nil))
	application.Store.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   config.Get("cookie.secure").(bool),
	}
	dbConfig := config.Get("database").(*toml.TomlTree)
	application.DbMap = models.GetDbMap(
		dbConfig.Get("user").(string),
		dbConfig.Get("password").(string),
		dbConfig.Get("hostname").(string),
		dbConfig.Get("port").(string),
		dbConfig.Get("database").(string))

	application.CsrfProtection = &CsrfProtection{
		Key:    config.Get("csrf.key").(string),
		Cookie: config.Get("csrf.cookie").(string),
		Header: config.Get("csrf.header").(string),
		Secure: config.Get("cookie.secure").(bool),
	}

	application.Config = config
}

var funcMap = template.FuncMap{
	"minus": minus,
	"plus":  plus,
	"round": round,
}

func minus(a, b int64) string {
	return strconv.FormatInt(a-b, 10)
}

func plus(a, b int64) string {
	return strconv.FormatInt(a+b, 10)
}

func round(val float64) int {
	if val < 0 {
		return int(val - 0.5)
	}
	return int(val + 0.5)
}

func (application *Application) LoadTemplates() error {
	var templates []string

	fn := func(path string, f os.FileInfo, err error) error {
		if f.IsDir() != true && strings.HasSuffix(f.Name(), ".html") {
			templates = append(templates, path)
		}
		return nil
	}

	err := filepath.Walk(application.Config.Get("general.template_path").(string), fn)
	if err != nil {
		return err
	}

	t := template.New("dcrstakepool").Funcs(funcMap)
	application.Template = template.Must(t.ParseFiles(templates...))
	return nil
}

func (application *Application) Close() {
	application.Logger.Info("Bye!")
}

// Route returns a Goji web.HandlerType (a route) for the method named "route"
// of the specified controller instance. The returned route handler sets the
// default content type to "text/html", calls the specified controller method,
// saves the session used in the request, retrieves any header key-value pairs
// stored in the c.Env["ResponseHeaderMap"] and sets them in the response
// header, and writes the response code (and body unless 500 code) to the
// response writer.
func (application *Application) Route(controller interface{}, route string) interface{} {
	fn := func(c web.C, w http.ResponseWriter, r *http.Request) {
		c.Env["Content-Type"] = "text/html"

		methodValue := reflect.ValueOf(controller).MethodByName(route)
		methodInterface := methodValue.Interface()
		method := methodInterface.(func(c web.C, r *http.Request) (string, int))

		body, code := method(c, r)

		if session, exists := c.Env["Session"]; exists {
			err := session.(*sessions.Session).Save(r, w)
			if err != nil {
				application.Logger.Errorf("Can't save session: %v", err)
			}
		}

		if respHeader, exists := c.Env["ResponseHeaderMap"]; exists {
			if hdrMap, ok := respHeader.(map[string]string); ok {
				for key, val := range hdrMap {
					w.Header().Set(key, val)
				}
			}
		}

		switch code {
		case http.StatusOK, http.StatusProcessing, http.StatusServiceUnavailable:
			if _, exists := c.Env["Content-Type"]; exists {
				w.Header().Set("Content-Type", c.Env["Content-Type"].(string))
			}
			w.WriteHeader(code)
			io.WriteString(w, body)
		case http.StatusSeeOther, http.StatusFound:
			http.Redirect(w, r, body, code)
		case http.StatusInternalServerError:
			http.Error(w, http.StatusText(500), 500)
		}
	}
	return fn
}
