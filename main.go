package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/jhillyerd/enmime"
	"github.com/kvannotten/mailstrip"
	log "github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
	"github.com/urfave/cli"
)

var (
	port               int
	expectedSecret     string
	emailMapping       string
	baseDomain         string
	gsmTrunk           string
	gsmUsername        string
	gsmPassword        string
	awsAccessKeyID     string
	awsSecretAccessKey string
	awsRegion          string
	logLevel           string

	emailToGSMPortMap map[string]string
	gsmPortToEmailMap map[string]string
)

type SNSMessage struct {
	Type             string    `json:"Type"`
	MessageID        string    `json:"MessageId"`
	Token            string    `json:"Token"`
	TopicArn         string    `json:"TopicArn"`
	Message          string    `json:"Message"`
	SubscribeURL     string    `json:"SubscribeURL"`
	Timestamp        time.Time `json:"Timestamp"`
	SignatureVersion string    `json:"SignatureVersion"`
	Signature        string    `json:"Signature"`
	SigningCertURL   string    `json:"SigningCertURL"`
}

type SESMessage struct {
	NotificationType string `json:"notificationType"`
	Mail             struct {
		Timestamp        time.Time `json:"timestamp"`
		Source           string    `json:"source"`
		MessageID        string    `json:"messageId"`
		Destination      []string  `json:"destination"`
		HeadersTruncated bool      `json:"headersTruncated"`
		Headers          []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"headers"`
		CommonHeaders struct {
			ReturnPath string   `json:"returnPath"`
			From       []string `json:"from"`
			Date       string   `json:"date"`
			To         []string `json:"to"`
			MessageID  string   `json:"messageId"`
			Subject    string   `json:"subject"`
		} `json:"commonHeaders"`
	} `json:"mail"`
	Receipt struct {
		Timestamp            time.Time `json:"timestamp"`
		ProcessingTimeMillis int       `json:"processingTimeMillis"`
		Recipients           []string  `json:"recipients"`
		SpamVerdict          struct {
			Status string `json:"status"`
		} `json:"spamVerdict"`
		VirusVerdict struct {
			Status string `json:"status"`
		} `json:"virusVerdict"`
		SpfVerdict struct {
			Status string `json:"status"`
		} `json:"spfVerdict"`
		DkimVerdict struct {
			Status string `json:"status"`
		} `json:"dkimVerdict"`
		DmarcVerdict struct {
			Status string `json:"status"`
		} `json:"dmarcVerdict"`
		Action struct {
			Type     string `json:"type"`
			TopicArn string `json:"topicArn"`
			Encoding string `json:"encoding"`
		} `json:"action"`
	} `json:"receipt"`
	Content string `json:"content"`
}

type UnauthorizedSenderError struct {
	Sender string
}

func (e *UnauthorizedSenderError) Error() string {
	return fmt.Sprintf("unauthorized sender: %s", e.Sender)
}

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello from smsproxy 3.0")
}

func doPostMessage(w http.ResponseWriter, r *http.Request) {
	secret := r.URL.Query().Get("secret")
	if secret == "" || secret != expectedSecret {
		log.Errorf("doPostMessage: request has invalid secret: %s\n", secret)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	switch snsMessageType := r.Header.Get("X-Amz-Sns-Message-Type"); snsMessageType {
	case "SubscriptionConfirmation":
		var snsMessage SNSMessage
		err := json.NewDecoder(r.Body).Decode(&snsMessage)
		if err != nil {
			log.Errorf("doPostMessage: error while parsing SNS message body: %s\n", err)
			w.WriteHeader(http.StatusOK)
			return
		}
		err = confirmSNSSubscription(snsMessage.SubscribeURL)
		if err != nil {
			log.Errorf("doPostMessage: failed to subscribe to SNS topic: %s\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		log.Infof("subscribed to SNS topic: %s\n", snsMessage.TopicArn)
		w.WriteHeader(http.StatusOK)
		return
	case "Notification":
		var sesMessage SESMessage
		err := json.NewDecoder(r.Body).Decode(&sesMessage)
		if err != nil {
			log.Errorf("doPostMessage: error while parsing SES message body: %s\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		err = sendTextMessage(sesMessage)
		if err != nil {
			log.Errorf("doPostMessage: failed to send text message: %s\n", err)

			switch err.(type) {
			case *UnauthorizedSenderError:
				w.WriteHeader(http.StatusUnauthorized)
				return
			default:
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		return
	case "":
		log.Errorf("doPostMessage: received request with no SNS message type")
		w.WriteHeader(http.StatusBadRequest)
		return
	default:
		log.Errorf("doPostMessage: received request with an unknown SNS message type: %s\n", snsMessageType)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
}

func doGetMessage(w http.ResponseWriter, r *http.Request) {
	secret := r.URL.Query().Get("secret")
	if secret == "" || secret != expectedSecret {
		log.Errorf("doGetMessage: request has invalid secret: %s\n", secret)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	phoneNumber := r.URL.Query().Get("phonenumber")
	gsmPort := r.URL.Query().Get("port")
	message := r.URL.Query().Get("message")
	time := r.URL.Query().Get("time")

	if _, ok := gsmPortToEmailMap[gsmPort]; !ok {
		log.Errorf("doGetMessage: request has unmapped gsm port: %s\n", gsmPort)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	to := gsmPortToEmailMap[gsmPort]
	from := fmt.Sprintf("%s@%s", phoneNumber, baseDomain)
	subject := fmt.Sprintf("Incoming SMS from %s", phoneNumber)
	text := fmt.Sprintf("%s - %s - %s", time, gsmPort, message)

	log.Infof("doGetMessage: sending email: %s %s %s %s\n", from, to, subject, text)
	if err := sendMail(from, to, subject, text); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func getHTTPClient() *http.Client {
	return &http.Client{
		Timeout: time.Second * 30,
	}
}

func confirmSNSSubscription(url string) error {
	client := getHTTPClient()
	_, err := client.Get(url)
	if err != nil {
		log.Errorf("confirmSNSSubscription: error while accessing subscription URL %s: %s\n", url, err)
		return err
	}
	return nil
}

func sendTextMessage(sesMessage SESMessage) error {
	senderAddr := sesMessage.Mail.Source
	if _, ok := emailToGSMPortMap[senderAddr]; !ok {
		return &UnauthorizedSenderError{Sender: senderAddr}
	}

	destAddr := sesMessage.Mail.Destination[0]
	destNumber := strings.Split(destAddr, "@")[0]
	gsmPort := emailToGSMPortMap[senderAddr]

	rawEmail, err := base64.StdEncoding.DecodeString(sesMessage.Content)
	if err != nil {
		return fmt.Errorf("sendTextMessage: unable to decode content")
	}

	// Strip all quoted replies and get the actual text content.
	env, _ := enmime.ReadEnvelope(bytes.NewReader(rawEmail))
	content := mailstrip.Parse(env.Text).String()

	// Strip all newlines.
	re := regexp.MustCompile(`\r?\n`)
	content = re.ReplaceAllString(content, " ")

	log.Infof("sendTextMessage: outgoing SMS: %s %s %s %s\n", senderAddr, destNumber, gsmPort, content)

	escapedContent := url.QueryEscape(content)
	query := fmt.Sprintf("/sendsms?username=%s&password=%s&port=%s&phonenumber=%s&message=%s",
		gsmUsername, gsmPassword, gsmPort, destNumber, escapedContent)

	log.Debugf("sendTextMessage: sending query: %s", gsmTrunk+query)
	req, err := http.NewRequest("GET", gsmTrunk+query, nil)

	client := getHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		sendErrorMail(senderAddr, destNumber, gsmPort, content, err.Error())
		return fmt.Errorf("sendTextMessage: unable to send query to GSM trunk: %s\n", err)
	}
	defer resp.Body.Close()

	log.Debugf("sendTextMessage: response status:", resp.Status)
	log.Debugf("sendTextMessage: response headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	log.Debugf("sendTextMessage: response body:", string(body))
	return nil
}

func processEmailMapping() error {
	emailToGSMPortMap = make(map[string]string)
	gsmPortToEmailMap = make(map[string]string)

	pairs := strings.Split(emailMapping, ",")
	if len(pairs) == 1 && pairs[0] == "" {
		return fmt.Errorf("processEmailMapping: cannot have an empty email map")
	}

	for _, pair := range pairs {
		parts := strings.Split(pair, ":")
		if len(parts) != 2 {
			return fmt.Errorf("processEmailMapping: missing map in entry: \"%s\"\n", pair)
		}

		email, port := parts[0], parts[1]
		if email == "" || port == "" {
			return fmt.Errorf("processEmailMapping: invalid map entry: \"%s\"\n", pair)
		}

		emailToGSMPortMap[email] = port
		gsmPortToEmailMap[port] = email
	}

	log.Debugf("processEmailMapping: email mappings: %+v", emailToGSMPortMap)
	log.Debugf("processEmailMapping: gsm port mappings: %+v", gsmPortToEmailMap)
	return nil
}

func sendErrorMail(senderAddr string, destNumber string, gsmPort string, content string, errMsg string) error {
	from := "noreply@" + baseDomain
	subject := fmt.Sprintf("SMS Sending Failure: %s", destNumber)
	text := fmt.Sprintf("Failed to send SMS to %s\n\nGSM port: %s\nContent: %s\n\nReason: %s",
		destNumber, gsmPort, content, errMsg)

	if err := sendMail(from, senderAddr, subject, text); err != nil {
		return err
	}
	return nil
}

func sendMail(from string, to string, subject string, text string) error {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(awsRegion),
	})

	svc := ses.New(sess)
	charset := "UTF-8"

	// Assemble the email.
	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			CcAddresses: []*string{},
			ToAddresses: []*string{
				aws.String(to),
			},
		},
		Message: &ses.Message{
			Body: &ses.Body{
				Text: &ses.Content{
					Charset: aws.String(charset),
					Data:    aws.String(text),
				},
			},
			Subject: &ses.Content{
				Charset: aws.String(charset),
				Data:    aws.String(subject),
			},
		},
		Source: aws.String(from),
	}

	// Attempt to send the email.
	result, err := svc.SendEmail(input)

	// Display error messages if they occur.
	if err != nil {
		log.Errorf("sendMail: error sending email to %s: %s\n", to, err.Error())
		return fmt.Errorf("sendMail: error sending email to %s: %s\n", to, err.Error())
	}

	log.Infof("sendMail: email sent to address: " + to)
	log.Debugf("sendMail: %+v", result)
	return nil
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
			Name:        "email-map",
			Value:       "",
			Usage:       "email:gsm-port mapping, separated by commas",
			EnvVar:      "EMAIL_MAPPING",
			Destination: &emailMapping,
		},
		cli.StringFlag{
			Name:        "base-domain",
			Value:       "example.com",
			Usage:       "base domain",
			EnvVar:      "BASE_DOMAIN",
			Destination: &baseDomain,
		},
		cli.StringFlag{
			Name:        "gsm-trunk",
			Value:       "http://localhost:8081",
			Usage:       "gsm trunk",
			EnvVar:      "GSM_TRUNK",
			Destination: &gsmTrunk,
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
			Name:        "aws-access-key-id",
			Value:       "",
			Usage:       "aws access key id",
			EnvVar:      "AWS_ACCESS_KEY_ID",
			Destination: &awsAccessKeyID,
		},
		cli.StringFlag{
			Name:        "aws-secret-access-key",
			Value:       "",
			Usage:       "aws secret access key",
			EnvVar:      "AWS_SECRET_ACCESS_KEY",
			Destination: &awsSecretAccessKey,
		},
		cli.StringFlag{
			Name:        "aws-region",
			Value:       "",
			Usage:       "aws region",
			EnvVar:      "AWS_REGION",
			Destination: &awsSecretAccessKey,
		},
		cli.StringFlag{
			Name:        "log-level",
			Value:       "info",
			Usage:       "log level",
			EnvVar:      "LOG_LEVEL",
			Destination: &logLevel,
		},
	}

	app.Action = func(c *cli.Context) error {
		level, err := log.ParseLevel(logLevel)
		if err != nil {
			log.Fatal(err)
		}
		log.SetLevel(level)

		if err := processEmailMapping(); err != nil {
			log.Fatal(err)
		}

		log.Infof("smsproxy listening on port %d\n", port)
		router := mux.NewRouter()
		router.HandleFunc("/", index).Methods("GET")
		router.HandleFunc("/messages", doPostMessage).Methods("POST")
		router.HandleFunc("/messages", doGetMessage).Methods("GET")
		log.Fatal(http.ListenAndServe(":"+strconv.Itoa(port), router))
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
