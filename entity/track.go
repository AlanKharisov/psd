package entity

import "net/http"

type trackWriter struct {
	http.ResponseWriter
	wroteHeader bool
}
