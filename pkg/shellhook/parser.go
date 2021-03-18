package shellhook

import (
	"fmt"
	"strings"
	"unicode"
)

type state uint32

const (
	firstChar state = iota
	stringField
	regularField
)

// Parse reads a configuration file and returns a parsed config
func Parse(config string) ([]Config, error) {
	tokens, err := splitTokens(config)
	if err != nil {
		return []Config{}, err
	}
	result, err := tokensToConfig(tokens)
	if err != nil {
		return []Config{}, err
	}
	return result, nil
}

func splitTokens(config string) ([]string, error) {
	var (
		tokens  = []string{}
		state   = firstChar
		builder = strings.Builder{}
		reader  = strings.NewReader(config)
	)

	for reader.Len() > 0 {
		r, _, err := reader.ReadRune()
		if err != nil {
			return []string{}, err
		}

		switch state {
		case firstChar:
			if unicode.IsSpace(r) {
				continue
			} else if r == '"' {
				state = stringField
			} else {
				state = regularField
				builder.WriteRune(r)
			}

		case stringField:
			if r == '\\' {
				n, _, rerr := reader.ReadRune()
				if rerr != nil {
					return []string{}, err
				}
				switch n {
				case 'n':
					builder.WriteRune('\n')
				case '\\':
					builder.WriteRune('\\')
				case '"':
					builder.WriteRune('"')
				}
			} else if r == '"' {
				tokens = append(tokens, builder.String())
				builder.Reset()
				state = firstChar
			} else {
				builder.WriteRune(r)
			}

		case regularField:
			if unicode.IsSpace(r) {
				tokens = append(tokens, builder.String())
				builder.Reset()
				state = firstChar
			} else {
				builder.WriteRune(r)
			}
		}
	}

	if builder.Len() > 0 {
		tokens = append(tokens, builder.String())
	}

	return tokens, nil
}

func tokensToConfig(tokens []string) ([]Config, error) {
	configs := []Config{}
	it := 0

	next := func() string {
		it++
		return tokens[it-1]
	}

	for it < len(tokens) {
		s := next()
		cur := &Config{}
		if len(configs) > 0 {
			cur = &configs[len(configs)-1]
		}

		switch s {
		case "path":
			configs = append(configs, Config{Path: next()})
		case "repo":
			cur.Repo = next()
		case "secret":
			cur.Secret = next()
		case "name":
			cur.Filters = append(cur.Filters, Filter{Type: "name", Value: next()})
		case "email":
			cur.Filters = append(cur.Filters, Filter{Type: "email", Value: next()})
		case "branch":
			cur.Filters = append(cur.Filters, Filter{Type: "branch", Value: next()})
		case "event":
			cur.Events = append(cur.Events, Event{Type: next(), Script: next()})
		default:
			return []Config{}, fmt.Errorf("unrecognized token: %s", s)
		}
	}

	return configs, nil
}
