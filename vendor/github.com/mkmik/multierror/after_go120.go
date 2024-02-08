//go:build go1.20
// +build go1.20

package multierror

// Split returns the underlying list of errors wrapped in a multierror.
//
// A multierror is an error tha implements Unwrap() []error (see https://pkg.go.dev/errors)
// Errors produced by multierror.Join implement Unwrap() []error.
func Split(err error) []error {
	u, ok := err.(interface {
		Unwrap() []error
	})
	if !ok {
		return []error{err}
	}
	return u.Unwrap()
}

func (e *Error) Unwrap() []error {
	return e.errs
}
