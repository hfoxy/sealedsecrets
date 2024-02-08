//go:build !go1.20
// +build !go1.20

package multierror

// Split returns the underlying list of errors wrapped in a multierror.
// If err is not a multierror, then a singleton list is returned.
func Split(err error) []error {
	if me, ok := err.(*Error); ok {
		return me.errs
	} else {
		return []error{err}
	}
}
