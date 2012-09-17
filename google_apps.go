package google_app

import (
	"code.google.com/p/gorilla/sessions"
	"github.com/fduraffourg/go-openid"
	"log"
	"net/http"
	"net/url"
)

// GoogleAppsHandler "middleware". 
// Wraps the passed HandlerFunc with google apps authentication
// 
// Example: 
//   http.HandleFunc("/", google_app.ProtectionHandler("jadedpixel.com", NotFound))
func ProtectionHandler(domain string, app http.HandlerFunc) http.HandlerFunc {
	store := sessions.NewCookieStore([]byte(domain))

	return func(w http.ResponseWriter, r *http.Request) {

		session, _ := store.Get(r, "login")

		log.Print(r.URL.Path)

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

		log.Printf("%v", session)

		if session.Values["id"] == nil {

			// Store the return_to url in the session to that we can sent people to the right spot
			currentUrl := url.URL{Path: r.URL.Path, RawQuery: r.URL.RawQuery}
			session.Values["return_to"] = currentUrl.String()
			log.Printf("Will send you back to %s", currentUrl.String())
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
