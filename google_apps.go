package google_apps

import (
	"net/http"
	"net/url"

	"github.com/akavel/go-openid"
	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(""))

//Identity receives the identity that's associated with the session.
func Identity(r *http.Request) string {
	session, _ := store.Get(r, "login")
	return session.Values["id"].(string)
}

//IsAuthenticated returns if is the request authenticated.
func IsAuthenticated(r *http.Request) bool {
	session, _ := store.Get(r, "login")
	return session.Values["id"] != nil
}

//ProtectionHandler is a  GoogleAppsHandler "middleware".
// Wraps the passed HandlerFunc with google apps authentication
//
// Example:
//   http.HandleFunc("/", google_app.ProtectionHandler("jadedpixel.com", NotFound))
func ProtectionHandler(domain string, app http.HandlerFunc) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "login")

		if r.FormValue("openid.mode") == "id_res" {
			_, id, err := openid.Verify(r.URL.String())

			if err != nil {
				http.Error(w, "Not authenticated", http.StatusForbidden)
				return
			}

			session.Values["id"] = id

			url := session.Values["return_to"].(string)
			if url == "" {
				url = "/"
			}

			delete(session.Values, "return_to")

			session.Save(r, w)

			http.Redirect(w, r, url, http.StatusFound)
			return
		}

		if session.Values["id"] == nil {

			// Store the return_to url in the session to that we can sent people to the right spot
			currentUrl := url.URL{Path: r.URL.Path, RawQuery: r.URL.RawQuery}
			session.Values["return_to"] = currentUrl.String()
			session.Save(r, w)

			// Get the auth url that we need for this.
			// We will use the current url minus the query string as a return place so that we can ensure
			// that this handler gets it back. We can't guess in what kind of sub paths this handler may be
			// installed otherwise
			url, err := openid.GetRedirectURL("https://www.google.com/accounts/o8/site-xrds?hd="+domain, "http://"+r.Host, r.URL.Path)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, url, http.StatusFound)
			return
		}

		app(w, r)
	}
}
