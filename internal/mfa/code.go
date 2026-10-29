package mfa

import (
	"strconv"
	"strings"
)


func isTOTPCode(value string) bool {
	if len(value) != Digits {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func trimCode(code string) string {
	return strings.TrimSpace(code)
}

func itoa(n int) string { return strconv.Itoa(n) }
