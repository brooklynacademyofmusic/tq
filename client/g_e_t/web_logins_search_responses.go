// Code generated by go-swagger; DO NOT EDIT.

package g_e_t

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

// WebLoginsSearchReader is a Reader for the WebLoginsSearch structure.
type WebLoginsSearchReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *WebLoginsSearchReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewWebLoginsSearchOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewWebLoginsSearchDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewWebLoginsSearchOK creates a WebLoginsSearchOK with default headers values
func NewWebLoginsSearchOK() *WebLoginsSearchOK {
	return &WebLoginsSearchOK{}
}

/*
WebLoginsSearchOK describes a response with status code 200, with default header values.

OK
*/
type WebLoginsSearchOK struct {
	Payload []*models.WebLogin
}

// IsSuccess returns true when this web logins search o k response has a 2xx status code
func (o *WebLoginsSearchOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this web logins search o k response has a 3xx status code
func (o *WebLoginsSearchOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this web logins search o k response has a 4xx status code
func (o *WebLoginsSearchOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this web logins search o k response has a 5xx status code
func (o *WebLoginsSearchOK) IsServerError() bool {
	return false
}

// IsCode returns true when this web logins search o k response a status code equal to that given
func (o *WebLoginsSearchOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the web logins search o k response
func (o *WebLoginsSearchOK) Code() int {
	return 200
}

func (o *WebLoginsSearchOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/WebLogins/Search][%d] webLoginsSearchOK %s", 200, payload)
}

func (o *WebLoginsSearchOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/WebLogins/Search][%d] webLoginsSearchOK %s", 200, payload)
}

func (o *WebLoginsSearchOK) GetPayload() []*models.WebLogin {
	return o.Payload
}

func (o *WebLoginsSearchOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewWebLoginsSearchDefault creates a WebLoginsSearchDefault with default headers values
func NewWebLoginsSearchDefault(code int) *WebLoginsSearchDefault {
	return &WebLoginsSearchDefault{
		_statusCode: code,
	}
}

/*
WebLoginsSearchDefault describes a response with status code -1, with default header values.

Error
*/
type WebLoginsSearchDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this web logins search default response has a 2xx status code
func (o *WebLoginsSearchDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this web logins search default response has a 3xx status code
func (o *WebLoginsSearchDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this web logins search default response has a 4xx status code
func (o *WebLoginsSearchDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this web logins search default response has a 5xx status code
func (o *WebLoginsSearchDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this web logins search default response a status code equal to that given
func (o *WebLoginsSearchDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the web logins search default response
func (o *WebLoginsSearchDefault) Code() int {
	return o._statusCode
}

func (o *WebLoginsSearchDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/WebLogins/Search][%d] WebLogins_Search default %s", o._statusCode, payload)
}

func (o *WebLoginsSearchDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/WebLogins/Search][%d] WebLogins_Search default %s", o._statusCode, payload)
}

func (o *WebLoginsSearchDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *WebLoginsSearchDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}