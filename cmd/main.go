package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/peterbourgon/ff/v3"

	"github.com/yjp20/github-shellhook/pkg/shellhook"
)

func main() {
	fs := flag.NewFlagSet("shellhook", flag.ExitOnError)
	var (
		inline = fs.String("inline", "", "Inline configuration for shellhook")
		file   = fs.String("file", "", "File configuration for shellhook")
	)
	ff.Parse(fs, os.Args[1:], ff.WithEnvVarPrefix("SHELLHOOK"))
	config := ""
	if *inline != "" {
		config = *inline
	} else {
		buffer, err := ioutil.ReadFile(*file)
		if err != nil {
			log.Fatal(err)
		}
		config = string(buffer)
	}
	configs, err := shellhook.Parse(config)
	if err != nil {
		log.Fatal(err)
	}
	err = shellhook.Run(configs, ":4000", "/bin/bash")
	if err != nil {
		log.Fatal(err)
	}
}

/*
/build-site
	url https://github.com/yjp20/youngjin.io.git
	branch master
	secret 1234123434234
	event push
		""
	event


*/
