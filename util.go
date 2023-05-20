package wireproxy

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
)

const space = " "

func responseWith(req *http.Request, statusCode int) *http.Response {
	statusText := http.StatusText(statusCode)
	body := "wireproxy:" + space + req.Proto + space + strconv.Itoa(statusCode) + space + statusText + "\r\n"

	return &http.Response{
		StatusCode: statusCode,
		Status:     statusText,
		Proto:      req.Proto,
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}
