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

// PronounsGetReader is a Reader for the PronounsGet structure.
type PronounsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PronounsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPronounsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPronounsGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPronounsGetOK creates a PronounsGetOK with default headers values
func NewPronounsGetOK() *PronounsGetOK {
	return &PronounsGetOK{}
}

/*
PronounsGetOK describes a response with status code 200, with default header values.

OK
*/
type PronounsGetOK struct {
	Payload *models.Pronoun
}

// IsSuccess returns true when this pronouns get o k response has a 2xx status code
func (o *PronounsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this pronouns get o k response has a 3xx status code
func (o *PronounsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pronouns get o k response has a 4xx status code
func (o *PronounsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this pronouns get o k response has a 5xx status code
func (o *PronounsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this pronouns get o k response a status code equal to that given
func (o *PronounsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the pronouns get o k response
func (o *PronounsGetOK) Code() int {
	return 200
}

func (o *PronounsGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Pronouns/{id}][%d] pronounsGetOK %s", 200, payload)
}

func (o *PronounsGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Pronouns/{id}][%d] pronounsGetOK %s", 200, payload)
}

func (o *PronounsGetOK) GetPayload() *models.Pronoun {
	return o.Payload
}

func (o *PronounsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Pronoun)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPronounsGetDefault creates a PronounsGetDefault with default headers values
func NewPronounsGetDefault(code int) *PronounsGetDefault {
	return &PronounsGetDefault{
		_statusCode: code,
	}
}

/*
PronounsGetDefault describes a response with status code -1, with default header values.

Error
*/
type PronounsGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this pronouns get default response has a 2xx status code
func (o *PronounsGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this pronouns get default response has a 3xx status code
func (o *PronounsGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this pronouns get default response has a 4xx status code
func (o *PronounsGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this pronouns get default response has a 5xx status code
func (o *PronounsGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this pronouns get default response a status code equal to that given
func (o *PronounsGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the pronouns get default response
func (o *PronounsGetDefault) Code() int {
	return o._statusCode
}

func (o *PronounsGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Pronouns/{id}][%d] Pronouns_Get default %s", o._statusCode, payload)
}

func (o *PronounsGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Pronouns/{id}][%d] Pronouns_Get default %s", o._statusCode, payload)
}

func (o *PronounsGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PronounsGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}