package shellhook

import (
	"reflect"
	"testing"
)

func TestSplitTokens(t *testing.T) {
	testCases := []struct {
		name   string
		str    string
		answer []string
	}{
		{
			"good",
			"what are the \"Tokens \\\"looking like\"\nhere \"new\nline\" end",
			[]string{
				"what",
				"are",
				"the",
				"Tokens \"looking like",
				"here",
				"new\nline",
				"end",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token, _ := splitTokens(tc.str)

			if len(tc.answer) != len(token) {
				t.Errorf("tokens and answer has different lengths: got %d, want %d", len(token), len(tc.answer))
				return
			}

			for index, got := range token {
				want := tc.answer[index]
				if want != got {
					t.Errorf("returned tokens is not equal to the answer: got %s, want %s", got, want)
					return
				}
			}
		})
	}
}

func TestTokensToConfig(t *testing.T) {
	testCases := []struct {
		name   string
		tokens []string
		answer []Config
	}{
		{
			"single",
			[]string{
				"path",
				"/hook/here",
				"secret",
				"1234",
				"branch",
				"master",
				"repo",
				"name/repo",
				"name",
				"authorsname",
				"email",
				"authorsemail",
				"event",
				"push",
				"git pull",
			},
			[]Config{
				{
					Path:   "/hook/here",
					Repo:   "name/repo",
					Secret: "1234",
					Filters: []Filter{
						{
							Type:  "branch",
							Value: "master",
						},
						{
							Type:  "name",
							Value: "authorsname",
						},
						{
							Type:  "email",
							Value: "authorsemail",
						},
					},
					Events: []Event{
						{
							Type:   "push",
							Script: "git pull",
						},
					},
				},
			},
		},
		{
			"double",
			[]string{
				"path",
				"/hook/here",
				"secret",
				"1234",
				"branch",
				"master",
				"repo",
				"name/repo",
				"name",
				"authorsname",
				"email",
				"authorsemail",
				"event",
				"push",
				"git pull",
				"path",
				"/hook/here",
				"secret",
				"1234",
				"branch",
				"master",
				"repo",
				"name/repo",
				"name",
				"authorsname",
				"email",
				"authorsemail",
				"event",
				"push",
				"git pull",
			},
			[]Config{
				{
					Path:   "/hook/here",
					Repo:   "name/repo",
					Secret: "1234",
					Filters: []Filter{
						{
							Type:  "branch",
							Value: "master",
						},
						{
							Type:  "name",
							Value: "authorsname",
						},
						{
							Type:  "email",
							Value: "authorsemail",
						},
					},
					Events: []Event{
						{
							Type:   "push",
							Script: "git pull",
						},
					},
				},
				{
					Path:   "/hook/here",
					Repo:   "name/repo",
					Secret: "1234",
					Filters: []Filter{
						{
							Type:  "branch",
							Value: "master",
						},
						{
							Type:  "name",
							Value: "authorsname",
						},
						{
							Type:  "email",
							Value: "authorsemail",
						},
					},
					Events: []Event{
						{
							Type:   "push",
							Script: "git pull",
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configs, _ := tokensToConfig(tc.tokens)

			if !reflect.DeepEqual(tc.answer, configs) {
				t.Errorf("configs and answer are different: got %+v, want %+v", configs, tc.answer)
				return
			}
		})
	}
}
