// Package apns sends push notifications through Apple Push Notification
// service with token-based authentication: an ES256 JWT made from the team's
// APNs auth key (.p8), sent over HTTP/2.
package apns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Hosts of the two APNs environments.
const (
	ProductionURL = "https://api.push.apple.com"
	SandboxURL    = "https://api.sandbox.push.apple.com"
)

// Apple rejects provider tokens older than an hour and refreshes more often
// than every 20 minutes.
const tokenLifetime = 40 * time.Minute

var idPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)

// ErrUnregistered means the device token is no longer valid for this app
// (the app was removed, or the token is for another app or environment).
// Forget the token.
var ErrUnregistered = errors.New("device token is no longer valid")

// Error is a rejection by APNs that may pass (rate limits, outages, a
// provider token problem).
type Error struct {
	Status int
	Reason string
}

func (e *Error) Error() string { return fmt.Sprintf("APNs %d: %s", e.Status, e.Reason) }

// Alert is one notification.
type Alert struct {
	Title string
	Body  string
	// Thread groups notifications on the lock screen.
	Thread string
	// CollapseID replaces an earlier notification with the same id.
	CollapseID string
	// TimeSensitive breaks through Focus (needs the app's entitlement).
	TimeSensitive bool
	// Expires: APNs drops the notification if the phone is unreachable
	// until then.
	Expires time.Time
	// Data is delivered to the app under the "jarvis" key.
	Data map[string]string
}

// Config identifies the sender.
type Config struct {
	KeyFile string // AuthKey_XXXXXXXXXX.p8
	KeyID   string
	TeamID  string
	Topic   string // the app's bundle id
}

// Client sends notifications. It is safe for concurrent use.
type Client struct {
	key    *ecdsa.PrivateKey
	keyID  string
	teamID string
	topic  string
	http   *http.Client
	// Hosts per environment ("production", "sandbox"); tests replace them.
	hosts map[string]string
	now   func() time.Time

	mu       sync.Mutex
	token    string
	issuedAt time.Time
}

// New loads the auth key.
func New(c Config) (*Client, error) {
	if !idPattern.MatchString(c.KeyID) || !idPattern.MatchString(c.TeamID) {
		return nil, errors.New("APNs key id and team id are 10 characters of A-Z and 0-9")
	}
	if c.Topic == "" {
		return nil, errors.New("APNs topic (the app's bundle id) is required")
	}
	data, err := os.ReadFile(c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("APNs key: %w", err)
	}
	key, err := parseKey(data)
	if err != nil {
		return nil, fmt.Errorf("APNs key %s: %w", c.KeyFile, err)
	}
	return &Client{
		key: key, keyID: c.KeyID, teamID: c.TeamID, topic: c.Topic,
		// HTTP/2 is negotiated over TLS; one connection carries every push.
		http:  &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{ForceAttemptHTTP2: true}},
		hosts: map[string]string{"production": ProductionURL, "sandbox": SandboxURL},
		now:   time.Now,
	}, nil
}

func parseKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("not a PEM file")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an EC private key")
	}
	return key, nil
}

// providerToken returns the current JWT, making a new one when it is old
// (or when `rejected` is the one APNs just refused).
func (c *Client) providerToken(rejected string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.token != rejected && c.now().Sub(c.issuedAt) < tokenLifetime {
		return c.token, nil
	}
	now := c.now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": c.teamID, "iat": now.Unix()})
	token.Header["kid"] = c.keyID
	signed, err := token.SignedString(c.key)
	if err != nil {
		return "", err
	}
	c.token, c.issuedAt = signed, now
	return signed, nil
}

// Send delivers an alert to a device in an environment ("production" or
// "sandbox"). It returns ErrUnregistered for dead tokens and *Error for
// other rejections.
func (c *Client) Send(ctx context.Context, environment, deviceToken string, a Alert) error {
	host, ok := c.hosts[environment]
	if !ok {
		return fmt.Errorf("unknown APNs environment %q", environment)
	}
	body, err := payload(a)
	if err != nil {
		return err
	}
	var rejected string
	for attempt := 0; ; attempt++ {
		token, err := c.providerToken(rejected)
		if err != nil {
			return err
		}
		status, reason, err := c.post(ctx, host+"/3/device/"+deviceToken, token, a, body)
		if err != nil {
			return err
		}
		switch {
		case status == http.StatusOK:
			return nil
		case status == http.StatusGone || reason == "BadDeviceToken" || reason == "DeviceTokenNotForTopic":
			return ErrUnregistered
		case status == http.StatusForbidden && reason == "ExpiredProviderToken" && attempt == 0:
			rejected = token // make a fresh one and try once more
			continue
		}
		return &Error{Status: status, Reason: reason}
	}
}

func (c *Client) post(ctx context.Context, url, token string, a Alert, body []byte) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("authorization", "bearer "+token)
	req.Header.Set("apns-topic", c.topic)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10")
	if !a.Expires.IsZero() {
		req.Header.Set("apns-expiration", strconv.FormatInt(a.Expires.Unix(), 10))
	}
	if a.CollapseID != "" {
		req.Header.Set("apns-collapse-id", a.CollapseID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("APNs: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var failure struct {
		Reason string `json:"reason"`
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		_ = json.Unmarshal(data, &failure)
	}
	return resp.StatusCode, failure.Reason, nil
}

// payload is the APNs JSON: the visible alert and the app's data.
func payload(a Alert) ([]byte, error) {
	aps := map[string]any{
		"alert": map[string]string{"title": a.Title, "body": a.Body},
		"sound": "default",
	}
	if a.Thread != "" {
		aps["thread-id"] = a.Thread
	}
	if a.TimeSensitive {
		aps["interruption-level"] = "time-sensitive"
	}
	out := map[string]any{"aps": aps}
	if len(a.Data) > 0 {
		out["jarvis"] = a.Data
	}
	body, err := json.Marshal(out)
	if err == nil && len(body) > 4096 {
		err = errors.New("APNs payload is larger than 4 KB")
	}
	return body, err
}

// WithHosts points the client at other hosts (tests).
func (c *Client) WithHosts(hosts map[string]string, client *http.Client) *Client {
	c.hosts, c.http = hosts, client
	return c
}
