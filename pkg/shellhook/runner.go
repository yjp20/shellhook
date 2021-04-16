package shellhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
)

func verifySignature(body []byte, secret string, hash string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	computed := mac.Sum(nil)
	computedString := "sha256=" + hex.EncodeToString(computed)
	return hash == computedString
}

// Run starts a web server based on the passed in configuration
func Run(configs []Config, port string, shell string) error {
	handle := func(w http.ResponseWriter, r *http.Request) {
		var obj githubResponse
		matched := false
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte("cannot read body"))
			return
		}
		err = json.Unmarshal(body, &obj)
		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte("cannot decode string as json" + err.Error()))
			return
		}

		for _, config := range configs {
			if config.Path != r.URL.Path {
				continue
			}
			if len(config.Repo) > 0 && config.Repo != obj.Repository.FullName {
				continue
			}
			filterMismatch := false
			for _, filter := range config.Filters {
				switch filter.Type {
				case "name":
					if filter.Value != obj.Pusher.Name {
						filterMismatch = true
					}
				case "email":
					if filter.Value != obj.Pusher.Email {
						filterMismatch = true
					}
				case "branch":
					if filter.Value != obj.Ref && "refs/heads/"+filter.Value != obj.Ref {
						filterMismatch = true
					}
				}
			}
			if filterMismatch {
				continue
			}
			log.Printf("Matched at '%s'", r.URL.Path)
			matched = true
			if err != nil {
				log.Panic(err)
			}

			if config.Secret != "" && !verifySignature(body, config.Secret, r.Header.Get("X-Hub-Signature-256")) {
				w.WriteHeader(401)
				w.Write([]byte("secret doesn't match"))
				log.Println("Request without matching signature was sent!")
				continue
			}

			var errors []string
			for _, event := range config.Events {
				if event.Type != r.Header.Get("X-Github-Event") {
					continue
				}
				cmd := exec.Command("/bin/sh", "-c", event.Script)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				err := cmd.Run()
				if err != nil {
					errors = append(errors, err.Error())
				}
			}

			if len(errors) > 0 {
				w.WriteHeader(500)
				w.Write([]byte(fmt.Sprintf("errors: %v+", errors)))
				return
			}

			w.WriteHeader(200)
			w.Write([]byte("ok"))
		}

		if !matched {
			w.WriteHeader(404)
			w.Write([]byte("no match"))
			log.Printf("No match")
		}
	}

	err := http.ListenAndServe(port, http.HandlerFunc(handle))
	return err
}
