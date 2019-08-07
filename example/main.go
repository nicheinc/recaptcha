package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
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
)

func main() {
	flag.Parse()

	client = recaptcha.NewClient(*secretKey)

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

	tmpl, err := template.New("template.html").ParseFiles("./template.html")
	if err != nil {
		http.Error(w,
			fmt.Sprintf("Error parsing html template: %s\n", err),
			http.StatusInternalServerError,
		)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w,
			fmt.Sprintf("Error executing template: %s", err),
			http.StatusInternalServerError,
		)
		return
	}
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("g-recaptcha-response")
	if token == "" {
		http.Error(w, "Form submission missing g-recaptcha-response parameter", http.StatusBadRequest)
		return
	}
	userIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w,
			fmt.Sprintf("Error parsing remote addr: %s", err),
			http.StatusBadRequest,
		)
		return
	}

	response, err := client.Fetch(context.Background(), token, userIP)
	if err != nil {
		http.Error(w,
			fmt.Sprintf("Error making request to token verification endpoint: %s", err),
			http.StatusInternalServerError,
		)
		return
	}

	out, err := json.MarshalIndent(response, "", "    ")
	if err != nil {
		http.Error(w,
			fmt.Sprintf("Error marshalling verification endpoint response: %s\n", err),
			http.StatusInternalServerError,
		)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(out); err != nil {
		http.Error(w,
			fmt.Sprintf("Error writing response: %s\n", err),
			http.StatusInternalServerError,
		)
		return
	}
}
