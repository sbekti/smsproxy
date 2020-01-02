package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/urfave/cli"
)

var (
	port           int
	expectedSecret string
	email          string
	domain         string
	gsmTrunk       string
	gsmPort        string
	gsmUsername    string
	gsmPassword    string
	mailgunUrl     string
	mailgunAPIKey  string
)

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello from smsproxy")
}

func sendMessage(w http.ResponseWriter, r *http.Request) {
	secret := r.URL.Query().Get("secret")
	if secret == "" || secret != expectedSecret {
		fmt.Printf("Received sendMessage request with invalid secret: %s\n", secret)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	r.ParseMultipartForm(0)

	sender := r.FormValue("sender")
	if sender == "" || sender != email {
		fmt.Printf("Received sendMessage request with invalid sender: %s\n", sender)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	recipient := r.FormValue("recipient")
	recipient = strings.Split(recipient, "@")[0]

	content := r.FormValue("stripped-text")
	re := regexp.MustCompile(`\r?\n`)
	content = re.ReplaceAllString(content, " ")

	fmt.Printf("Received sendMessage request: %s %s %s\n", recipient, sender, content)

	escapedContent := url.QueryEscape(content)
	query := fmt.Sprintf("/sendsms?username=%s&password=%s&port=%s&phonenumber=%s&message=%s",
		gsmUsername, gsmPassword, gsmPort, recipient, escapedContent)

	fmt.Printf("Sending query: %s", gsmTrunk+query)
	req, err := http.NewRequest("GET", gsmTrunk+query, nil)

	client := &http.Client{
		Timeout: time.Second * 30,
	}
	resp, err := client.Do(req)
	if err != nil {
		errMsg := fmt.Sprintf("%s", err)
		fmt.Println(errMsg)
		sendErrorMail(sender, recipient, content, errMsg)
		w.WriteHeader(http.StatusOK)
		return
	}
	defer resp.Body.Close()

	fmt.Println("response Status:", resp.Status)
	fmt.Println("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response Body:", string(body))

	fmt.Fprintf(w, "done!")
}

func receiveMessage(w http.ResponseWriter, r *http.Request) {
	secret := r.URL.Query().Get("secret")
	if secret == "" || secret != expectedSecret {
		fmt.Printf("Received receiveMessage request with invalid secret: %s\n", secret)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	phoneNumber := r.URL.Query().Get("phonenumber")
	port := r.URL.Query().Get("port")
	message := r.URL.Query().Get("message")
	time := r.URL.Query().Get("time")

	from := fmt.Sprintf("%s@%s", phoneNumber, domain)
	subject := fmt.Sprintf("Incoming SMS from %s", phoneNumber)
	text := fmt.Sprintf("%s - %s - %s", time, port, message)
	
	fmt.Printf("Sending email: %s %s %s %s\n", from, email, subject, text)
	sendMail(from, email, subject, text)
}

func sendErrorMail(to string, recipient string, content string, errMsg string) {
	subject := fmt.Sprintf("SMS Sending Failure: %s", recipient)
	text := fmt.Sprintf("Failed to send SMS to %s\n\nContent: %s\n\nReason: %s", recipient, content, errMsg)
	sendMail(domain, to, subject, text)
}

func sendMail(from string, to string, subject string, text string) {
	data := url.Values{}
	data.Add("from", from)
	data.Add("to", to)
	data.Add("subject", subject)
	data.Add("text", text)

	req, err := http.NewRequest("POST", mailgunUrl, strings.NewReader(data.Encode()))
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(mailgunAPIKey)))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	client := &http.Client{
		Timeout: time.Second * 30,
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("response Status:", resp.Status)
	fmt.Println("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response Body:", string(body))
}

func main() {
	app := cli.NewApp()

	app.Flags = []cli.Flag{
		&cli.IntFlag{
			Name:        "port",
			Value:       8080,
			Usage:       "port number to listen on",
			EnvVar:      "PORT",
			Destination: &port,
		},
		cli.StringFlag{
			Name:        "secret",
			Value:       "changeme",
			Usage:       "secret",
			EnvVar:      "SECRET",
			Destination: &expectedSecret,
		},
		cli.StringFlag{
			Name:        "email",
			Value:       "someone@domain.com",
			Usage:       "email",
			EnvVar:      "EMAIL",
			Destination: &email,
		},
		cli.StringFlag{
			Name:        "domain",
			Value:       "domain.com",
			Usage:       "domain",
			EnvVar:      "DOMAIN",
			Destination: &domain,
		},
		cli.StringFlag{
			Name:        "gsm-trunk",
			Value:       "http://localhost:8081",
			Usage:       "gsm trunk",
			EnvVar:      "GSM_TRUNK",
			Destination: &gsmTrunk,
		},
		cli.StringFlag{
			Name:        "gsm-port",
			Value:       "http://localhost:8081",
			Usage:       "gsm port",
			EnvVar:      "GSM_PORT",
			Destination: &gsmPort,
		},
		cli.StringFlag{
			Name:        "gsm-username",
			Value:       "",
			Usage:       "gsm username",
			EnvVar:      "GSM_USERNAME",
			Destination: &gsmUsername,
		},
		cli.StringFlag{
			Name:        "gsm-password",
			Value:       "",
			Usage:       "gsm password",
			EnvVar:      "GSM_PASSWORD",
			Destination: &gsmPassword,
		},
		cli.StringFlag{
			Name:        "mailgun-url",
			Value:       "",
			Usage:       "mailgun url",
			EnvVar:      "MAILGUN_URL",
			Destination: &mailgunUrl,
		},
		cli.StringFlag{
			Name:        "mailgun-api-key",
			Value:       "",
			Usage:       "mailgun api key",
			EnvVar:      "MAILGUN_API_KEY",
			Destination: &mailgunAPIKey,
		},
	}

	app.Action = func(c *cli.Context) error {
		fmt.Printf("Server listening on port %d\n", port)
		router := mux.NewRouter()
		router.HandleFunc("/", index).Methods("GET")
		router.HandleFunc("/messages", sendMessage).Methods("POST")
		router.HandleFunc("/messages", receiveMessage).Methods("GET")
		log.Fatal(http.ListenAndServe(":"+strconv.Itoa(port), router))
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
