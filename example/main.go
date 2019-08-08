package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/nicheinc/recaptcha"
)

var (
	secretKey = flag.String("secret-key", "", "reCAPTCHA secret key")
	siteKey   = flag.String("site-key", "", "reCAPTCHA site key")
	hostnames = flag.String("hostname", "localhost", "Valid hostnames (comma separated)")
	actions   = flag.String("action", "submit", "Valid actions (comma separated)")
	score     = flag.Float64("score", 0.5, "Minimum score threshold")
	port      = flag.Int("port", 80, "Port to run example server on")

	client *recaptcha.Client
)

func main() {
	flag.Parse()

	client = recaptcha.NewClient(*secretKey)

	http.HandleFunc("/", handler)
	http.HandleFunc("/submit", submitHandler)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", *port), nil); err != nil {
		log.Fatalf("Error serving requests: %s\n", err)
	}
}

type data struct {
	SiteKey string
}

func handler(w http.ResponseWriter, r *http.Request) {
	data := data{
		SiteKey: *siteKey,
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
	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "Form submission missing 'token' parameter", http.StatusBadRequest)
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

	if _, err := w.Write(out); err != nil {
		http.Error(w,
			fmt.Sprintf("Error writing response: %s\n", err),
			http.StatusInternalServerError,
		)
		return
	}

	var message string
	if err := response.Verify(
		recaptcha.Hostname(strings.Split(*hostnames, ",")...),
		recaptcha.Action(strings.Split(*actions, ",")...),
		recaptcha.Score(*score),
	); err != nil {
		message = fmt.Sprintf("\n\nToken is invalid: %s", err)
	} else {
		message = fmt.Sprintf("\n\nToken is valid")
	}

	if _, err := io.WriteString(w, message); err != nil {
		http.Error(w,
			fmt.Sprintf("Error writing response: %s\n", err),
			http.StatusInternalServerError,
		)
		return
	}
}
