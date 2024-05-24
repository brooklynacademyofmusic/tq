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

// PronounsUpdateReader is a Reader for the PronounsUpdate structure.
type PronounsUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PronounsUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPronounsUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPronounsUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPronounsUpdateOK creates a PronounsUpdateOK with default headers values
func NewPronounsUpdateOK() *PronounsUpdateOK {
	return &PronounsUpdateOK{}
}

/*
PronounsUpdateOK describes a response with status code 200, with default header values.

OK
*/
type PronounsUpdateOK struct {
	Payload *models.Pronoun
}

// IsSuccess returns true when this pronouns update o k response has a 2xx status code
func (o *PronounsUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this pronouns update o k response has a 3xx status code
func (o *PronounsUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pronouns update o k response has a 4xx status code
func (o *PronounsUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this pronouns update o k response has a 5xx status code
func (o *PronounsUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this pronouns update o k response a status code equal to that given
func (o *PronounsUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the pronouns update o k response
func (o *PronounsUpdateOK) Code() int {
	return 200
}

func (o *PronounsUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/Pronouns/{id}][%d] pronounsUpdateOK %s", 200, payload)
}

func (o *PronounsUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/Pronouns/{id}][%d] pronounsUpdateOK %s", 200, payload)
}

func (o *PronounsUpdateOK) GetPayload() *models.Pronoun {
	return o.Payload
}

func (o *PronounsUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Pronoun)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPronounsUpdateDefault creates a PronounsUpdateDefault with default headers values
func NewPronounsUpdateDefault(code int) *PronounsUpdateDefault {
	return &PronounsUpdateDefault{
		_statusCode: code,
	}
}

/*
PronounsUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type PronounsUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this pronouns update default response has a 2xx status code
func (o *PronounsUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this pronouns update default response has a 3xx status code
func (o *PronounsUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this pronouns update default response has a 4xx status code
func (o *PronounsUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this pronouns update default response has a 5xx status code
func (o *PronounsUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this pronouns update default response a status code equal to that given
func (o *PronounsUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the pronouns update default response
func (o *PronounsUpdateDefault) Code() int {
	return o._statusCode
}

func (o *PronounsUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/Pronouns/{id}][%d] Pronouns_Update default %s", o._statusCode, payload)
}

func (o *PronounsUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/Pronouns/{id}][%d] Pronouns_Update default %s", o._statusCode, payload)
}

func (o *PronounsUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PronounsUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
