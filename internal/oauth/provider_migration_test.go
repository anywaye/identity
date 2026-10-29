package oauth


import (
	"os"
	"regexp"
)

const connectedAccountProviderFile = "../../migrations/00008_connected_accounts.sql"

var connectedAccountProviderAdditions = []string{
	"../../migrations/00025_oauth_provider_microsoft.sql",
	"../../migrations/00026_oauth_provider_apple.sql",
}

var enumPattern = regexp.MustCompile(`(?i)CREATE\s+TYPE\s+oauth_provider\s+AS\s+ENUM\s*\(([^)]*)\)`)

var addValuePattern = regexp.MustCompile(`(?i)ALTER\s+TYPE\s+oauth_provider\s+ADD\s+VALUE\s+'([^']*)'`)

var quotedPattern = regexp.MustCompile(`'([^']*)'`)

func connectedAccountProviderEnum() (names []string, ok bool) {
	raw, err := os.ReadFile(connectedAccountProviderFile)
	if err != nil {
		return nil, false
	}

	match := enumPattern.FindSubmatch(raw)
	if match == nil {
		return nil, false
	}

	for _, quoted := range quotedPattern.FindAllSubmatch(match[1], -1) {
		names = append(names, string(quoted[1]))
	}
	if len(names) == 0 {
		return nil, false
	}

	for _, file := range connectedAccountProviderAdditions {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, false
		}
		for _, m := range addValuePattern.FindAllSubmatch(raw, -1) {
			names = append(names, string(m[1]))
		}
	}
	return names, true
}

func contains(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}
