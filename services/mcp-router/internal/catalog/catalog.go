// Package catalog lists well-known remote MCP servers users can connect.
// URLs and authentication requirements are from each vendor's documentation
// (checked September 2026).
package catalog

import "sort"

// Auth is how the router authenticates to a server.
type Auth int

const (
	// OAuth is the MCP authorization flow (OAuth 2.1 + PKCE).
	OAuth Auth = iota + 1
	// Bearer is a static token the user supplies (API key, PAT).
	Bearer
)

// Registration is how the router obtains an OAuth client for a server.
type Registration int

const (
	// Automatic: pre-registered if configured, otherwise dynamic registration.
	Automatic Registration = iota
	// Preregistered: the vendor requires an app the operator registers.
	Preregistered
)

// Entry is a catalog server.
type Entry struct {
	Slug         string
	Name         string
	URL          string
	Auth         Auth
	Registration Registration
	Notes        string
}

// ClientCredentials are an operator-registered OAuth app.
type ClientCredentials struct {
	ClientID     string
	ClientSecret string
}

var builtin = []Entry{
	{
		Slug: "atlassian", Name: "Atlassian (Jira, Confluence)", URL: "https://mcp.atlassian.com/v2/mcp",
		Auth: OAuth, Notes: "Your Atlassian admin may need to allow the Jarvis redirect domain.",
	},
	{Slug: "clickup", Name: "ClickUp", URL: "https://mcp.clickup.com/mcp", Auth: OAuth},
	{Slug: "linear", Name: "Linear", URL: "https://mcp.linear.app/mcp", Auth: OAuth},
	{Slug: "notion", Name: "Notion", URL: "https://mcp.notion.com/mcp", Auth: OAuth},
	{
		Slug: "github", Name: "GitHub", URL: "https://api.githubcopilot.com/mcp/", Auth: Bearer,
		Notes: "Use a fine-grained personal access token with only the repositories and permissions Jarvis needs.",
	},
	{
		Slug: "slack", Name: "Slack", URL: "https://mcp.slack.com/mcp", Auth: OAuth, Registration: Preregistered,
		Notes: "Requires a Slack app (internal or directory-published) configured as MCP_OAUTH_SLACK_CLIENT_ID/SECRET.",
	},
	{
		Slug: "gmail", Name: "Gmail", URL: "https://gmailmcp.googleapis.com/mcp/v1", Auth: OAuth, Registration: Preregistered,
		Notes: "Developer preview. Requires a Google Cloud OAuth client configured as MCP_OAUTH_GMAIL_CLIENT_ID/SECRET.",
	},
}

// Catalog is the built-in list plus the operator's OAuth apps.
type Catalog struct {
	entries map[string]Entry
	clients map[string]ClientCredentials
}

// New builds the catalog; `clients` maps a slug to its registered OAuth app.
func New(clients map[string]ClientCredentials) *Catalog {
	c := &Catalog{entries: map[string]Entry{}, clients: clients}
	for _, entry := range builtin {
		c.entries[entry.Slug] = entry
	}
	return c
}

// Get returns an entry by slug.
func (c *Catalog) Get(slug string) (Entry, bool) {
	entry, ok := c.entries[slug]
	return entry, ok
}

// Available reports whether an entry can be connected with this configuration.
func (c *Catalog) Available(entry Entry) bool {
	if entry.Registration != Preregistered {
		return true
	}
	_, ok := c.clients[entry.Slug]
	return ok
}

// Client returns the operator's OAuth app for a slug, if any.
func (c *Catalog) Client(slug string) (ClientCredentials, bool) {
	credentials, ok := c.clients[slug]
	return credentials, ok
}

// Entries returns every entry sorted by name.
func (c *Catalog) Entries() []Entry {
	out := make([]Entry, 0, len(c.entries))
	for _, entry := range c.entries {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Slugs of entries that accept operator-registered OAuth apps.
func Slugs() []string {
	slugs := make([]string, 0, len(builtin))
	for _, entry := range builtin {
		if entry.Auth == OAuth {
			slugs = append(slugs, entry.Slug)
		}
	}
	return slugs
}
