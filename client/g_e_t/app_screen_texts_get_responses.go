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

// AppScreenTextsGetReader is a Reader for the AppScreenTextsGet structure.
type AppScreenTextsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AppScreenTextsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAppScreenTextsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewAppScreenTextsGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewAppScreenTextsGetOK creates a AppScreenTextsGetOK with default headers values
func NewAppScreenTextsGetOK() *AppScreenTextsGetOK {
	return &AppScreenTextsGetOK{}
}

/*
AppScreenTextsGetOK describes a response with status code 200, with default header values.

OK
*/
type AppScreenTextsGetOK struct {
	Payload *models.AppScreenText
}

// IsSuccess returns true when this app screen texts get o k response has a 2xx status code
func (o *AppScreenTextsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this app screen texts get o k response has a 3xx status code
func (o *AppScreenTextsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this app screen texts get o k response has a 4xx status code
func (o *AppScreenTextsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this app screen texts get o k response has a 5xx status code
func (o *AppScreenTextsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this app screen texts get o k response a status code equal to that given
func (o *AppScreenTextsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the app screen texts get o k response
func (o *AppScreenTextsGetOK) Code() int {
	return 200
}

func (o *AppScreenTextsGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/AppScreenTexts/{id}][%d] appScreenTextsGetOK %s", 200, payload)
}

func (o *AppScreenTextsGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/AppScreenTexts/{id}][%d] appScreenTextsGetOK %s", 200, payload)
}

func (o *AppScreenTextsGetOK) GetPayload() *models.AppScreenText {
	return o.Payload
}

func (o *AppScreenTextsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AppScreenText)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAppScreenTextsGetDefault creates a AppScreenTextsGetDefault with default headers values
func NewAppScreenTextsGetDefault(code int) *AppScreenTextsGetDefault {
	return &AppScreenTextsGetDefault{
		_statusCode: code,
	}
}

/*
AppScreenTextsGetDefault describes a response with status code -1, with default header values.

Error
*/
type AppScreenTextsGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this app screen texts get default response has a 2xx status code
func (o *AppScreenTextsGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this app screen texts get default response has a 3xx status code
func (o *AppScreenTextsGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this app screen texts get default response has a 4xx status code
func (o *AppScreenTextsGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this app screen texts get default response has a 5xx status code
func (o *AppScreenTextsGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this app screen texts get default response a status code equal to that given
func (o *AppScreenTextsGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the app screen texts get default response
func (o *AppScreenTextsGetDefault) Code() int {
	return o._statusCode
}

func (o *AppScreenTextsGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/AppScreenTexts/{id}][%d] AppScreenTexts_Get default %s", o._statusCode, payload)
}

func (o *AppScreenTextsGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/AppScreenTexts/{id}][%d] AppScreenTexts_Get default %s", o._statusCode, payload)
}

func (o *AppScreenTextsGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *AppScreenTextsGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
