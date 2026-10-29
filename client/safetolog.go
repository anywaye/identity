package client


import (
	"fmt"
	"reflect"
	"strings"
)

// SafeToLog renders any value for a log record with credential-SHAPED strings
// replaced by `Redacted`.
//
// The name is a statement rather than a description: it answers the question a caller
// has at the call site — "may I log this?" — and it has to be readable in a diff
// review, where `fmt.Sprintf("%v", …)` on a credential-bearing type looks entirely
// ordinary.
//
// It is a function taking `any` rather than twenty typed entry points, because a
// caller holding a value should not have to know which of the generated shapes it is.
//
// ## THE LIMIT OF THIS ONE, AND WHICH OF THE TWO TO REACH FOR
//
// **This function does not know your credential.** It recognizes the `anywaye_`
// prefix, a JWS, and header lines — shapes. A bare session token is 43 base64url
// characters with no prefix and no dots, and there is nothing about it that
// distinguishes it from an opaque id, so this function passes it through.
//
// `(*Client).SafeToLog` is the one that knows: it uses the client's redactor, which
// holds this client's own credential, so an exact match is caught too. **If you have
// a client, use that.** This function is for a value you hold with no client to hand
// — a token read out of a config file, a struct built by a test.
func SafeToLog(value any) string {
	if value == nil {
		return "<nil>"
	}
	return safeToLog(reflect.ValueOf(value), 0, "", Redactor{})
}

// SafeToLog renders any value with THIS CLIENT'S credential known, so an exact
// match is redacted as well as the shapes.
//
// Strictly stronger than the package-level `SafeToLog`, and the one to reach for
// when a client is in hand — which, in a caller that has constructed one, it always
// is. The package-level function exists for the value-with-no-client case.
func (c *Client) SafeToLog(value any) string {
	if value == nil {
		return "<nil>"
	}
	return safeToLog(reflect.ValueOf(value), 0, "", c.redactor)
}

func safeToLog(v reflect.Value, depth int, indent string, redact Redactor) string {
	if depth > 6 || !v.IsValid() {
		return "…"
	}

	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return "<nil>"
		}
		return safeToLog(v.Elem(), depth+1, indent, redact)

	case reflect.Struct:
		var out strings.Builder

		name := v.Type().String()
		if name == "time.Time" {
			out.WriteString(redact.String(fmt.Sprintf("%v", v.Interface())))
			return out.String()
		}

		out.WriteString(name + "{")
		t := v.Type()
		wrote := false

		for i := 0; i < v.NumField(); i++ {
			field := t.Field(i)
			if !field.IsExported() {
				continue
			}

			if wrote {
				out.WriteString(" ")
			}
			wrote = true

			out.WriteString(field.Name + ": ")
			out.WriteString(safeToLog(v.Field(i), depth+1, indent+"  ", redact))
		}

		out.WriteString("}")
		return out.String()

	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return "[]"
		}
		var out strings.Builder
		out.WriteString("[")
		for i := 0; i < v.Len() && i < 16; i++ {
			if i > 0 {
				out.WriteString(" ")
			}
			out.WriteString(safeToLog(v.Index(i), depth+1, indent, redact))
		}
		out.WriteString("]")
		return out.String()

	case reflect.Map:
		var out strings.Builder
		out.WriteString("map[")
		for i, key := range v.MapKeys() {
			if i > 0 {
				out.WriteString(" ")
			}
			if i >= 16 {
				out.WriteString("…")
				break
			}
			out.WriteString(safeToLog(key, depth+1, indent, redact))
			out.WriteString(":")
			out.WriteString(safeToLog(v.MapIndex(key), depth+1, indent, redact))
		}
		out.WriteString("]")
		return out.String()

	default:
		return redact.String(fmt.Sprintf("%v", v.Interface()))
	}
}
