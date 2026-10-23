package management

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/router-for-me/CLIProxyAPIHome/internal/auth/claude"
)

const (
	anthropicManualAuthURL       = "https://claude.com/cai/oauth/authorize"
	anthropicManualRedirectURI   = "https://platform.claude.com/oauth/code/callback"
	anthropicManualOAuthScope    = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
	anthropicOAuthFlowCallback   = "callback"
	anthropicOAuthFlowManual     = "manual"
)

type normalizedOAuthCallback struct {
	state        string
	code         string
	error        string
	codeStatePair bool
}

func buildAnthropicAuthURLForFlow(flow, state string, pkce *pkceCodes) (string, string, string, error) {
	switch strings.ToLower(strings.TrimSpace(flow)) {
	case "", anthropicOAuthFlowCallback:
		return anthropicOAuthFlowCallback, anthropicRedirectURI, buildAnthropicAuthURL(state, pkce), nil
	case anthropicOAuthFlowManual:
		return anthropicOAuthFlowManual, anthropicManualRedirectURI, buildAnthropicManualAuthURL(state, pkce), nil
	default:
		return "", "", "", fmt.Errorf("unsupported anthropic oauth flow")
	}
}

func buildAnthropicManualAuthURL(state string, pkce *pkceCodes) string {
	params := url.Values{
		"code":                  {"true"},
		"client_id":             {claude.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {anthropicManualRedirectURI},
		"scope":                 {anthropicManualOAuthScope},
		"code_challenge":        {pkce.CodeChallenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}
	return anthropicManualAuthURL + "?" + params.Encode()
}

func normalizeV8OAuthCallback(req oauthCallbackRequest) (normalizedOAuthCallback, error) {
	input := normalizedOAuthCallback{
		state: strings.TrimSpace(req.State),
		code:  strings.TrimSpace(req.Code),
		error: strings.TrimSpace(req.Error),
	}
	if rawURL := strings.TrimSpace(req.RedirectURL); rawURL != "" {
		parsedURL, errParse := url.Parse(rawURL)
		if errParse != nil {
			return normalizedOAuthCallback{}, fmt.Errorf("invalid redirect_url")
		}
		query := parsedURL.Query()
		urlState, errValue := singleCallbackQueryValue(query, "state")
		if errValue != nil {
			return normalizedOAuthCallback{}, errValue
		}
		urlCode, errValue := singleCallbackQueryValue(query, "code")
		if errValue != nil {
			return normalizedOAuthCallback{}, errValue
		}
		urlError, errValue := singleCallbackQueryValue(query, "error")
		if errValue != nil {
			return normalizedOAuthCallback{}, errValue
		}
		if urlError == "" {
			urlError, errValue = singleCallbackQueryValue(query, "error_description")
			if errValue != nil {
				return normalizedOAuthCallback{}, errValue
			}
		}
		if errMerge := mergeCallbackValue(&input.state, urlState, "state does not match redirect_url"); errMerge != nil {
			return normalizedOAuthCallback{}, errMerge
		}
		if errMerge := mergeCallbackValue(&input.code, urlCode, "code does not match redirect_url"); errMerge != nil {
			return normalizedOAuthCallback{}, errMerge
		}
		if errMerge := mergeCallbackValue(&input.error, urlError, "error does not match redirect_url"); errMerge != nil {
			return normalizedOAuthCallback{}, errMerge
		}
	}

	if strings.Contains(input.code, "#") {
		parts := strings.Split(input.code, "#")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return normalizedOAuthCallback{}, fmt.Errorf("invalid code/state pair")
		}
		pairState := strings.TrimSpace(parts[1])
		if input.state != "" && input.state != pairState {
			return normalizedOAuthCallback{}, fmt.Errorf("state does not match code/state pair")
		}
		input.code = strings.TrimSpace(parts[0])
		input.state = pairState
		input.codeStatePair = true
	}
	return input, nil
}

func singleCallbackQueryValue(query url.Values, key string) (string, error) {
	values, ok := query[key]
	if !ok {
		return "", nil
	}
	if len(values) != 1 {
		return "", fmt.Errorf("invalid redirect_url")
	}
	return strings.TrimSpace(values[0]), nil
}

func mergeCallbackValue(target *string, value, mismatchMessage string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if *target != "" && *target != value {
		return fmt.Errorf("%s", mismatchMessage)
	}
	*target = value
	return nil
}

func splitAnthropicCodeState(code, state string) (string, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return "", fmt.Errorf("authorization code is required")
	}
	if !strings.Contains(code, "#") {
		return code, nil
	}
	parts := strings.Split(code, "#")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", fmt.Errorf("invalid code/state pair")
	}
	if strings.TrimSpace(parts[1]) != strings.TrimSpace(state) {
		return "", fmt.Errorf("state does not match code/state pair")
	}
	return strings.TrimSpace(parts[0]), nil
}

func anthropicRedirectURIForSession(data map[string]any) (string, error) {
	flow := strings.ToLower(strings.TrimSpace(stringFromAny(data["flow"])))
	redirectURI := strings.TrimSpace(stringFromAny(data["redirect_uri"]))
	if flow == "" && redirectURI == "" {
		return anthropicRedirectURI, nil
	}
	if flow == "" || flow == anthropicOAuthFlowCallback {
		if redirectURI == "" || redirectURI == anthropicRedirectURI {
			return anthropicRedirectURI, nil
		}
		return "", fmt.Errorf("unsupported anthropic oauth redirect uri")
	}
	if flow == anthropicOAuthFlowManual && redirectURI == anthropicManualRedirectURI {
		return anthropicManualRedirectURI, nil
	}
	return "", fmt.Errorf("unsupported anthropic oauth flow or redirect uri")
}
