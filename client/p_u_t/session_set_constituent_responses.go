// Code generated by go-swagger; DO NOT EDIT.

package p_u_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// SessionSetConstituentReader is a Reader for the SessionSetConstituent structure.
type SessionSetConstituentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SessionSetConstituentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSessionSetConstituentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSessionSetConstituentDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSessionSetConstituentOK creates a SessionSetConstituentOK with default headers values
func NewSessionSetConstituentOK() *SessionSetConstituentOK {
	return &SessionSetConstituentOK{}
}

/*
SessionSetConstituentOK describes a response with status code 200, with default header values.

OK
*/
type SessionSetConstituentOK struct {
	Payload []*models.WebConstituentDisplaySummary
}

// IsSuccess returns true when this session set constituent o k response has a 2xx status code
func (o *SessionSetConstituentOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this session set constituent o k response has a 3xx status code
func (o *SessionSetConstituentOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this session set constituent o k response has a 4xx status code
func (o *SessionSetConstituentOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this session set constituent o k response has a 5xx status code
func (o *SessionSetConstituentOK) IsServerError() bool {
	return false
}

// IsCode returns true when this session set constituent o k response a status code equal to that given
func (o *SessionSetConstituentOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the session set constituent o k response
func (o *SessionSetConstituentOK) Code() int {
	return 200
}

func (o *SessionSetConstituentOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Web/Session/{sessionKey}/Constituents][%d] sessionSetConstituentOK %s", 200, payload)
}

func (o *SessionSetConstituentOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Web/Session/{sessionKey}/Constituents][%d] sessionSetConstituentOK %s", 200, payload)
}

func (o *SessionSetConstituentOK) GetPayload() []*models.WebConstituentDisplaySummary {
	return o.Payload
}

func (o *SessionSetConstituentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSessionSetConstituentDefault creates a SessionSetConstituentDefault with default headers values
func NewSessionSetConstituentDefault(code int) *SessionSetConstituentDefault {
	return &SessionSetConstituentDefault{
		_statusCode: code,
	}
}

/*
SessionSetConstituentDefault describes a response with status code -1, with default header values.

Error
*/
type SessionSetConstituentDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this session set constituent default response has a 2xx status code
func (o *SessionSetConstituentDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this session set constituent default response has a 3xx status code
func (o *SessionSetConstituentDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this session set constituent default response has a 4xx status code
func (o *SessionSetConstituentDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this session set constituent default response has a 5xx status code
func (o *SessionSetConstituentDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this session set constituent default response a status code equal to that given
func (o *SessionSetConstituentDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the session set constituent default response
func (o *SessionSetConstituentDefault) Code() int {
	return o._statusCode
}

func (o *SessionSetConstituentDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Web/Session/{sessionKey}/Constituents][%d] Session_SetConstituent default %s", o._statusCode, payload)
}

func (o *SessionSetConstituentDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /Web/Session/{sessionKey}/Constituents][%d] Session_SetConstituent default %s", o._statusCode, payload)
}

func (o *SessionSetConstituentDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SessionSetConstituentDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}