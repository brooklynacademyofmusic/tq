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

// PronounsGetAllReader is a Reader for the PronounsGetAll structure.
type PronounsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PronounsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPronounsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPronounsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPronounsGetAllOK creates a PronounsGetAllOK with default headers values
func NewPronounsGetAllOK() *PronounsGetAllOK {
	return &PronounsGetAllOK{}
}

/*
PronounsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type PronounsGetAllOK struct {
	Payload []*models.Pronoun
}

// IsSuccess returns true when this pronouns get all o k response has a 2xx status code
func (o *PronounsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this pronouns get all o k response has a 3xx status code
func (o *PronounsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pronouns get all o k response has a 4xx status code
func (o *PronounsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this pronouns get all o k response has a 5xx status code
func (o *PronounsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this pronouns get all o k response a status code equal to that given
func (o *PronounsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the pronouns get all o k response
func (o *PronounsGetAllOK) Code() int {
	return 200
}

func (o *PronounsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Pronouns][%d] pronounsGetAllOK %s", 200, payload)
}

func (o *PronounsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Pronouns][%d] pronounsGetAllOK %s", 200, payload)
}

func (o *PronounsGetAllOK) GetPayload() []*models.Pronoun {
	return o.Payload
}

func (o *PronounsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPronounsGetAllDefault creates a PronounsGetAllDefault with default headers values
func NewPronounsGetAllDefault(code int) *PronounsGetAllDefault {
	return &PronounsGetAllDefault{
		_statusCode: code,
	}
}

/*
PronounsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type PronounsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this pronouns get all default response has a 2xx status code
func (o *PronounsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this pronouns get all default response has a 3xx status code
func (o *PronounsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this pronouns get all default response has a 4xx status code
func (o *PronounsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this pronouns get all default response has a 5xx status code
func (o *PronounsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this pronouns get all default response a status code equal to that given
func (o *PronounsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the pronouns get all default response
func (o *PronounsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *PronounsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Pronouns][%d] Pronouns_GetAll default %s", o._statusCode, payload)
}

func (o *PronounsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Pronouns][%d] Pronouns_GetAll default %s", o._statusCode, payload)
}

func (o *PronounsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PronounsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
