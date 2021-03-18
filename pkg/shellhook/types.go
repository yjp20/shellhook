package shellhook

// Config describes the configuration for the shellhook web server
type Config struct {
	Path    string
	Repo    string
	Secret  string
	Filters []Filter
	Events  []Event
}

// Filter describes the different filters that can be applied to specify the scope of a handler
type Filter struct {
	Type  string
	Value string
}

// Event describes the different script actions that are executed
type Event struct {
	Type   string
	Script string
}
