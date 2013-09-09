# GoogleAppsHandler "middleware". 

Wraps the passed HandlerFunc with google apps authentication
 
Example: 

    import "github.com/shopify/google_apps"

    http.HandleFunc("/", google_apps.ProtectionHandler("shopify.com", YourOwnHttpHandler))
