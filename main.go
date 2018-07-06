package main

import (
	"bytes"
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

var port int
var expectedSecret, expectedSender, upstream,
	mailgunURL, mailgunAPIKey, mailgunFrom string

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello")
}

func create(w http.ResponseWriter, r *http.Request) {
	secret := r.URL.Query().Get("secret")
	if secret == "" || secret != expectedSecret {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	r.ParseMultipartForm(0)

	sender := r.FormValue("sender")
	if sender == "" || sender != expectedSender {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	recipient := r.FormValue("recipient")
	recipient = strings.Split(recipient, "@")[0]

	content := r.FormValue("stripped-text")
	re := regexp.MustCompile(`\r?\n`)
	content = re.ReplaceAllString(content, " ")

	fmt.Printf("%s %s %s\n", recipient, sender, content)

	jsonStr := []byte(`{"recipient":"` + recipient + `","content":"` + content + `"}`)
	req, err := http.NewRequest("POST", upstream, bytes.NewBuffer(jsonStr))

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

func sendErrorMail(to string, recipient string, content string, errMsg string) {
	data := url.Values{}
	data.Add("from", mailgunFrom)
	data.Add("to", to)
	data.Add("subject", fmt.Sprintf("SMS Sending Failure: %s", recipient))

	text := fmt.Sprintf("Failed to send SMS to %s\n\nContent: %s\n\nReason: %s", recipient, content, errMsg)
	data.Add("text", text)

	req, err := http.NewRequest("POST", mailgunURL, strings.NewReader(data.Encode()))
	req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(mailgunAPIKey)))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	client := &http.Client{
		Timeout: time.Second * 30,
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%s", err)
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
		cli.IntFlag{
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
			Name:        "sender",
			Value:       "someone@domain.com",
			Usage:       "sender",
			EnvVar:      "SENDER",
			Destination: &expectedSender,
		},
		cli.StringFlag{
			Name:        "upstream",
			Value:       "http://localhost:8081",
			Usage:       "upstream url",
			EnvVar:      "UPSTREAM_URL",
			Destination: &upstream,
		},
		cli.StringFlag{
			Name:        "mailgun-url",
			Value:       "",
			Usage:       "mailgun url",
			EnvVar:      "MAILGUN_URL",
			Destination: &mailgunURL,
		},
		cli.StringFlag{
			Name:        "mailgun-api-key",
			Value:       "",
			Usage:       "mailgun api key",
			EnvVar:      "MAILGUN_API_KEY",
			Destination: &mailgunAPIKey,
		},
		cli.StringFlag{
			Name:        "mailgun-from",
			Value:       "",
			Usage:       "mailgun from",
			EnvVar:      "MAILGUN_FROM",
			Destination: &mailgunFrom,
		},
	}

	app.Action = func(c *cli.Context) error {
		fmt.Printf("Server listening on port %d\n", port)
		router := mux.NewRouter()
		router.HandleFunc("/", index).Methods("GET")
		router.HandleFunc("/", create).Methods("POST")
		log.Fatal(http.ListenAndServe(":"+strconv.Itoa(port), router))
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
