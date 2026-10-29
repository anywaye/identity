package mfa

import (
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
)


func hotpOptions(digits, algorithm string) (hotp.ValidateOpts, error) {
	var d otp.Digits
	switch digits {
	case "6":
		d = otp.DigitsSix
	case "8":
		d = otp.DigitsEight
	default:
		return hotp.ValidateOpts{}, fmt.Errorf("mfa: stored digit count %q is not one this service can verify", digits)
	}

	var a otp.Algorithm
	switch algorithm {
	case "SHA1":
		a = otp.AlgorithmSHA1
	default:
		return hotp.ValidateOpts{}, fmt.Errorf("mfa: stored algorithm %q is not one this service can verify", algorithm)
	}

	return hotp.ValidateOpts{Digits: d, Algorithm: a}, nil
}

// StepAt is the counter a time falls in.
//
// It is exported because the replay guard, the pruning query and the tests all
// need to name the same number, and three places that each compute
// unix/period by hand is three places a rounding convention can drift.
func StepAt(at time.Time, period time.Duration) int64 {
	if period <= 0 {
		period = Period
	}
	return at.UTC().Unix() / int64(period/time.Second)
}

// CandidateSteps is the ordered list of counters a code may match, nearest
// first.
//
// Nearest-first because that is the order in which a human's answer should be
// believed: a phone thirty seconds fast produces the next step's code, and the
// next step's code is in the window precisely so that phone still works. The
// ordering only decides which step gets recorded when a six-digit value
// coincidentally matches two candidates, which happens with probability 3e-6 —
// and when it does, recording the nearer one is the choice that a real user is
// more likely to be able to use again.
//
// The list is (2·SkewSteps + 1) long and never longer. A SkewSteps of two or
// more would make this nine entries, and every one of them is thirty more
// seconds of a phished code's life; see SkewSteps for why it is one.
func CandidateSteps(current int64, skew uint) []int64 {
	steps := make([]int64, 0, 2*int(skew)+1)
	steps = append(steps, current)
	for i := 1; i <= int(skew); i++ {
		steps = append(steps, current+int64(i), current-int64(i))
	}
	return steps
}

// MatchStep is the question this file exists to answer: which step, if any, does
// this code belong to?
//
// It walks CandidateSteps and asks the library about each one, so the answer is
// "step 2,914,455,123" rather than the library's "true". The difference is the
// replay guard: Store.ClaimStep records that number, and a bool could not be
// recorded.
//
// A malformed secret is a refusal, not a panic and not a match. The secret is
// base32 and comes from a column this service wrote, so a value that will not
// decode means the row is corrupt — and a corrupt credential must fail closed.
func MatchStep(secret, code string, now time.Time, digits, algorithm string, period time.Duration, skew uint) (int64, bool) {
	if secret == "" || code == "" {
		return 0, false
	}

	opts, err := hotpOptions(digits, algorithm)
	if err != nil {
		return 0, false
	}

	current := StepAt(now, period)
	for _, step := range CandidateSteps(current, skew) {
		if step < 0 {
			continue
		}
		ok, err := hotp.ValidateCustom(code, uint64(step), secret, opts)
		if err != nil || !ok {
			continue
		}
		return step, true
	}
	return 0, false
}

// Code is the TOTP code for an instant. It is what the authenticator app would
// be showing, and it exists so a test can produce a real code from a real secret
// rather than a fixture pasted in from somewhere.
//
// It is not a way to get a code for somebody else's credential: it needs the
// secret, and the secret is sealed at rest. The same function is exported by
// pquerna/otp for the same reason.
func Code(secret string, at time.Time) (string, error) {
	return totpCode(secret, at, DigitSix, AlgorithmSHA1, Period)
}

func totpCode(secret string, at time.Time, digits string, algorithm string, period time.Duration) (string, error) {
	opts, err := hotpOptions(digits, algorithm)
	if err != nil {
		return "", err
	}
	if period <= 0 {
		period = Period
	}
	step := StepAt(at, period)
	if step < 0 {
		return "", fmt.Errorf("mfa: refusing to generate a code for the instant %s", at)
	}
	return hotp.GenerateCodeCustom(secret, uint64(step), opts)
}

const (
	DigitSix      = "6"
	DigitEight    = "8"
	AlgorithmSHA1 = "SHA1"
)
