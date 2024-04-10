// Code generated by go-swagger; DO NOT EDIT.

package g_e_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// SessionGetReader is a Reader for the SessionGet structure.
type SessionGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SessionGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSessionGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /Web/Session/{sessionKey}] Session_Get", response, response.Code())
	}
}

// NewSessionGetOK creates a SessionGetOK with default headers values
func NewSessionGetOK() *SessionGetOK {
	return &SessionGetOK{}
}

/*
SessionGetOK describes a response with status code 200, with default header values.

OK
*/
type SessionGetOK struct {
	Payload *models.Session
}

// IsSuccess returns true when this session get o k response has a 2xx status code
func (o *SessionGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this session get o k response has a 3xx status code
func (o *SessionGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this session get o k response has a 4xx status code
func (o *SessionGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this session get o k response has a 5xx status code
func (o *SessionGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this session get o k response a status code equal to that given
func (o *SessionGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the session get o k response
func (o *SessionGetOK) Code() int {
	return 200
}

func (o *SessionGetOK) Error() string {
	return fmt.Sprintf("[GET /Web/Session/{sessionKey}][%d] sessionGetOK  %+v", 200, o.Payload)
}

func (o *SessionGetOK) String() string {
	return fmt.Sprintf("[GET /Web/Session/{sessionKey}][%d] sessionGetOK  %+v", 200, o.Payload)
}

func (o *SessionGetOK) GetPayload() *models.Session {
	return o.Payload
}

func (o *SessionGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Session)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}