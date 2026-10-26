package xrayconfig

// NotCarriedError is xray's refusal of a link for something xray cannot do
// but another engine does without weakening the link: the legacy VMess
// handshake, a transport or TCP header xray dropped. A refusal made for the
// link's safety (no TLS, skipped certificate verification, a weak cipher) is
// a plain error, so a caller can fall back on errors.As without moving a link
// to an engine that would run it in the clear.
type NotCarriedError struct{ Err error }

func (e NotCarriedError) Error() string { return e.Err.Error() }

func (e NotCarriedError) Unwrap() error { return e.Err }
