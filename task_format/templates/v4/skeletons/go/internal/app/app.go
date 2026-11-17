// Package app is the application (TODO(builder)).
package app

import "fmt"

// Handle answers one request.
func Handle(request string) map[string]string {
	return map[string]string{"answer": fmt.Sprintf("TODO: handle %q", request)}
}
