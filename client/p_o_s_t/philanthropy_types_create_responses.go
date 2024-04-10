// Code generated by go-swagger; DO NOT EDIT.

package p_o_s_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// PhilanthropyTypesCreateReader is a Reader for the PhilanthropyTypesCreate structure.
type PhilanthropyTypesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PhilanthropyTypesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPhilanthropyTypesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /ReferenceData/PhilanthropyTypes] PhilanthropyTypes_Create", response, response.Code())
	}
}

// NewPhilanthropyTypesCreateOK creates a PhilanthropyTypesCreateOK with default headers values
func NewPhilanthropyTypesCreateOK() *PhilanthropyTypesCreateOK {
	return &PhilanthropyTypesCreateOK{}
}

/*
PhilanthropyTypesCreateOK describes a response with status code 200, with default header values.

OK
*/
type PhilanthropyTypesCreateOK struct {
	Payload *models.PhilanthropyType
}

// IsSuccess returns true when this philanthropy types create o k response has a 2xx status code
func (o *PhilanthropyTypesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this philanthropy types create o k response has a 3xx status code
func (o *PhilanthropyTypesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this philanthropy types create o k response has a 4xx status code
func (o *PhilanthropyTypesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this philanthropy types create o k response has a 5xx status code
func (o *PhilanthropyTypesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this philanthropy types create o k response a status code equal to that given
func (o *PhilanthropyTypesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the philanthropy types create o k response
func (o *PhilanthropyTypesCreateOK) Code() int {
	return 200
}

func (o *PhilanthropyTypesCreateOK) Error() string {
	return fmt.Sprintf("[POST /ReferenceData/PhilanthropyTypes][%d] philanthropyTypesCreateOK  %+v", 200, o.Payload)
}

func (o *PhilanthropyTypesCreateOK) String() string {
	return fmt.Sprintf("[POST /ReferenceData/PhilanthropyTypes][%d] philanthropyTypesCreateOK  %+v", 200, o.Payload)
}

func (o *PhilanthropyTypesCreateOK) GetPayload() *models.PhilanthropyType {
	return o.Payload
}

func (o *PhilanthropyTypesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PhilanthropyType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}