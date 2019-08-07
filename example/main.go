package main

import (
	"context"
	"encoding/json"
	"flag"
	"html/template"
	"log"
	"net"
	"net/http"

	"github.com/nicheinc/recaptcha"
)

var (
	secretKey = flag.String("secret-key", "", "reCAPTCHA secret key")
	siteKey   = flag.String("site-key", "", "reCAPTCHA site key")
	action    = flag.String("action", "", "reCAPTCHA action")

	client *recaptcha.Client
	tmpl   *template.Template
)

func main() {
	flag.Parse()

	client = recaptcha.NewClient(*secretKey)

	var err error
	tmpl, err = template.New("template.html").ParseFiles("./template.html")
	if err != nil {
		log.Fatalf("Error parsing html template: %s\n", err)
	}

	http.HandleFunc("/", handler)
	http.HandleFunc("/submit", submitHandler)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Error serving requests: %s\n", err)
	}
}

type data struct {
	SiteKey string
	Action  string
}

func handler(w http.ResponseWriter, r *http.Request) {
	data := data{
		SiteKey: *siteKey,
		Action:  *action,
	}

	if err := tmpl.Execute(w, data); err != nil {
		log.Fatalf("Error executing template: %s", err)
	}
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("g-recaptcha-response")
	if token == "" {
		log.Fatalln("Form submission missing g-recaptcha-response")
	}
	userIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Fatalf("Error parsing remote addr: %s", err)
	}

	response, err := client.Fetch(context.Background(), token, userIP)
	if err != nil {
		log.Fatalf("Error making request to token verification endpoint: %s", err)
	}

	out, err := json.MarshalIndent(response, "", "    ")
	if err != nil {
		log.Fatalf("Error marshalling verification endpoint response: %s\n", err)
	}

	if _, err := w.Write(out); err != nil {
		log.Fatalf("Error writing response: %s\n", err)
	}
}
