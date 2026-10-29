package httpapi


import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

type openAPIDocument struct {
	Path string
	SpecVersion string
	InfoVersion string
	Operations map[operationKey]documentedOperation
}

type documentedOperation struct {
	Method string
	Path   string
	OperationID string
}

func (o documentedOperation) Label() string { return o.Method + " " + o.Path }

type operationKey struct {
	Method string
	Path   string
}

func (k operationKey) String() string { return k.Method + " " + k.Path }

var openAPIOperationKeys = map[string]string{
	"get":     "GET",
	"put":     "PUT",
	"post":    "POST",
	"delete":  "DELETE",
	"options": "OPTIONS",
	"head":    "HEAD",
	"patch":   "PATCH",
	"trace":   "TRACE",
}

var openAPIPathItemFields = map[string]bool{
	"summary": true, "description": true, "servers": true,
	"parameters": true, "$ref": true,
}

func readOpenAPIDocument(path string) (openAPIDocument, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return openAPIDocument{}, fmt.Errorf("could not read %s: %w", path, err)
	}

	doc := openAPIDocument{Path: path, Operations: map[operationKey]documentedOperation{}}
	lines := significantLines(string(raw))

	if doc.SpecVersion, err = topLevelScalar(path, lines, "openapi"); err != nil {
		return openAPIDocument{}, err
	}
	if doc.InfoVersion, err = infoScalar(path, lines, "version"); err != nil {
		return openAPIDocument{}, err
	}

	block, pathLevel, methodLevel, err := pathsBlock(path, lines)
	if err != nil {
		return openAPIDocument{}, err
	}

	for _, group := range groupByPathLevel(block, pathLevel) {
		key := strings.TrimSuffix(group[0].text, ":")
		number := group[0].number

		if !strings.HasPrefix(key, "/") {
			if openAPIPathItemFields[key] || strings.HasPrefix(key, "x-") {
				continue
			}
			return openAPIDocument{}, fmt.Errorf(
				"%s:%d — %q is not a valid OpenAPI path. Every key directly under `paths:` "+
					"is a path starting with `/`, or a field of the Path Item Object "+
					"(summary, description, servers, parameters, $ref, x-…). This reader "+
					"refuses the document rather than guessing which was meant.",
				path, number, key)
		}

		methods := make([]documentedOperation, 0, len(openAPIOperationKeys))
		for _, line := range group[1:] {
			if line.indent != methodLevel {
				continue
			}
			method, ok := openAPIOperationKeys[strings.TrimSuffix(line.text, ":")]
			if !ok {
				continue
			}
			methods = append(methods, documentedOperation{
				Method: method,
				Path:   key,
			})
		}

		if len(methods) == 0 {
			return openAPIDocument{}, fmt.Errorf(
				"%s:%d — the path %q has no operation under it. An OpenAPI path item with "+
					"no operation is not something a client can be generated from, and "+
					"skipping it would leave this check agreeing with a document that says "+
					"nothing about this route.",
				path, number, key)
		}

		for _, op := range methods {
			if err := doc.record(path, number, op); err != nil {
				return openAPIDocument{}, err
			}
		}
	}

	doc.readOperationIDs(groupByPathLevel(block, pathLevel), methodLevel)

	if len(doc.Operations) == 0 {
		return openAPIDocument{}, fmt.Errorf(
			"%s documents no operations at all. Two readers that both find nothing agree, "+
				"which is how a check over nothing goes green.", path)
	}
	return doc, nil
}

func (d *openAPIDocument) record(path string, number int, op documentedOperation) error {
	key := operationKey{Method: op.Method, Path: normalisePath(op.Path)}
	if existing, clash := d.Operations[key]; clash {
		return fmt.Errorf(
			"%s:%d — %s and %s both read as %s. They normalise onto one route, so a check "+
				"that could not see the collision would be blind to it.",
			path, number, existing.Label(), op.Label(), key)
	}
	d.Operations[key] = op
	return nil
}

func (d *openAPIDocument) readOperationIDs(groups [][]yamlLine, methodLevel int) {
	for _, group := range groups {
		key := strings.TrimSuffix(group[0].text, ":")
		if !strings.HasPrefix(key, "/") {
			continue
		}
		for _, line := range group[1:] {
			method, ok := openAPIOperationKeys[strings.TrimSuffix(line.text, ":")]
			if !ok || line.indent != methodLevel {
				continue
			}
			id, found := operationIDBelow(group[1:], line, methodLevel)
			if !found {
				continue
			}
			normalised := operationKey{Method: method, Path: normalisePath(key)}
			op := d.Operations[normalised]
			op.OperationID = id
			d.Operations[normalised] = op
		}
	}
}

func operationIDBelow(group []yamlLine, methodLine yamlLine, methodLevel int) (string, bool) {
	bodyLevel := -1
	for _, line := range group {
		if line.number <= methodLine.number {
			continue
		}
		if line.indent <= methodLevel {
			break
		}
		if bodyLevel < 0 {
			bodyLevel = line.indent
		}
		if line.indent != bodyLevel {
			continue
		}
		if value, ok := strings.CutPrefix(line.text, "operationId:"); ok {
			return strings.Trim(strings.TrimSpace(value), `"'`), true
		}
	}
	return "", false
}

func normalisePath(path string) string {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if segment != "" && (strings.HasPrefix(segment, "{") || strings.HasPrefix(segment, ":")) {
			segments[i] = "{}"
		}
	}
	trimmed := strings.TrimRight(strings.Join(segments, "/"), "/")
	if trimmed == "" {
		return "/"
	}
	return trimmed
}


type yamlLine struct {
	indent int
	text   string
	number int
}

func significantLines(contents string) []yamlLine {
	var out []yamlLine
	scanner := bufio.NewScanner(strings.NewReader(contents))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for number := 1; scanner.Scan(); number++ {
		raw := scanner.Text()
		stripped := strings.TrimLeft(raw, " ")
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		out = append(out, yamlLine{
			indent: len(raw) - len(stripped),
			text:   strings.TrimRight(stripped, " "),
			number: number,
		})
	}
	return out
}

func topLevelScalar(path string, lines []yamlLine, key string) (string, error) {
	for _, line := range lines {
		if line.indent != 0 {
			continue
		}
		if value, ok := strings.CutPrefix(line.text, key+":"); ok {
			return strings.Trim(strings.TrimSpace(value), `"'`), nil
		}
	}
	return "", fmt.Errorf(
		"%s has no top-level `%s:`. A document that does not say what it is cannot be "+
			"checked against anything, and this reader returns an error rather than an "+
			"empty one so a check over nothing cannot pass.", path, key)
}

func infoScalar(path string, lines []yamlLine, key string) (string, error) {
	for i, line := range lines {
		if line.indent != 0 || line.text != "info:" {
			continue
		}
		level := 0
		for _, child := range lines[i+1:] {
			if child.indent == 0 {
				break
			}
			if level == 0 {
				level = child.indent
			}
			if child.indent != level {
				continue
			}
			if value, ok := strings.CutPrefix(child.text, key+":"); ok {
				return strings.Trim(strings.TrimSpace(value), `"'`), nil
			}
		}
		break
	}
	return "", fmt.Errorf(
		"%s has no `info.version`. core requires it, and it is the only signal a consumer "+
			"has for attributing a deprecated endpoint to a release. Missing is an error "+
			"here, not an empty string.", path)
}

func pathsBlock(path string, lines []yamlLine) (block []yamlLine, pathLevel, methodLevel int, err error) {
	for i, line := range lines {
		if line.indent != 0 || line.text != "paths:" {
			continue
		}
		for _, child := range lines[i+1:] {
			if child.indent == 0 {
				break
			}
			block = append(block, child)
		}
		levels := distinctIndents(block)
		switch {
		case len(levels) == 0:
			return nil, 0, 0, fmt.Errorf(
				"%s documents no operations: nothing is under its `paths:` key. Two readers "+
					"that both find nothing agree, which is how a check over nothing goes green.", path)
		case len(levels) == 1:
			return nil, 0, 0, fmt.Errorf(
				"%s documents no operations: what is under `paths:` is one indentation level "+
					"deep, so there is no operation level below the path items.", path)
		}
		return block, levels[0], levels[1], nil
	}
	return nil, 0, 0, fmt.Errorf(
		"%s has no top-level `paths:` key. A reader that cannot find the document's paths "+
			"finds none, and a check over none passes — so this is an error, not an empty "+
			"result.", path)
}

func distinctIndents(block []yamlLine) []int {
	seen := map[int]bool{}
	var levels []int
	for _, line := range block {
		if !seen[line.indent] {
			seen[line.indent] = true
			levels = append(levels, line.indent)
		}
	}
	sort.Ints(levels)
	return levels
}

func groupByPathLevel(block []yamlLine, pathLevel int) [][]yamlLine {
	var groups [][]yamlLine
	for _, line := range block {
		if line.indent == pathLevel || len(groups) == 0 {
			groups = append(groups, []yamlLine{line})
			continue
		}
		groups[len(groups)-1] = append(groups[len(groups)-1], line)
	}
	return groups
}
