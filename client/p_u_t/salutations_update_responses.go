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

// SalutationsUpdateReader is a Reader for the SalutationsUpdate structure.
type SalutationsUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SalutationsUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSalutationsUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSalutationsUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSalutationsUpdateOK creates a SalutationsUpdateOK with default headers values
func NewSalutationsUpdateOK() *SalutationsUpdateOK {
	return &SalutationsUpdateOK{}
}

/*
SalutationsUpdateOK describes a response with status code 200, with default header values.

OK
*/
type SalutationsUpdateOK struct {
	Payload *models.Salutation
}

// IsSuccess returns true when this salutations update o k response has a 2xx status code
func (o *SalutationsUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this salutations update o k response has a 3xx status code
func (o *SalutationsUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this salutations update o k response has a 4xx status code
func (o *SalutationsUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this salutations update o k response has a 5xx status code
func (o *SalutationsUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this salutations update o k response a status code equal to that given
func (o *SalutationsUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the salutations update o k response
func (o *SalutationsUpdateOK) Code() int {
	return 200
}

func (o *SalutationsUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /CRM/Salutations/{salutationId}][%d] salutationsUpdateOK %s", 200, payload)
}

func (o *SalutationsUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /CRM/Salutations/{salutationId}][%d] salutationsUpdateOK %s", 200, payload)
}

func (o *SalutationsUpdateOK) GetPayload() *models.Salutation {
	return o.Payload
}

func (o *SalutationsUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Salutation)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSalutationsUpdateDefault creates a SalutationsUpdateDefault with default headers values
func NewSalutationsUpdateDefault(code int) *SalutationsUpdateDefault {
	return &SalutationsUpdateDefault{
		_statusCode: code,
	}
}

/*
SalutationsUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type SalutationsUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this salutations update default response has a 2xx status code
func (o *SalutationsUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this salutations update default response has a 3xx status code
func (o *SalutationsUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this salutations update default response has a 4xx status code
func (o *SalutationsUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this salutations update default response has a 5xx status code
func (o *SalutationsUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this salutations update default response a status code equal to that given
func (o *SalutationsUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the salutations update default response
func (o *SalutationsUpdateDefault) Code() int {
	return o._statusCode
}

func (o *SalutationsUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /CRM/Salutations/{salutationId}][%d] Salutations_Update default %s", o._statusCode, payload)
}

func (o *SalutationsUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /CRM/Salutations/{salutationId}][%d] Salutations_Update default %s", o._statusCode, payload)
}

func (o *SalutationsUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SalutationsUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}