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

// AssociationsUpdateReader is a Reader for the AssociationsUpdate structure.
type AssociationsUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AssociationsUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAssociationsUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewAssociationsUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewAssociationsUpdateOK creates a AssociationsUpdateOK with default headers values
func NewAssociationsUpdateOK() *AssociationsUpdateOK {
	return &AssociationsUpdateOK{}
}

/*
AssociationsUpdateOK describes a response with status code 200, with default header values.

OK
*/
type AssociationsUpdateOK struct {
	Payload *models.Association
}

// IsSuccess returns true when this associations update o k response has a 2xx status code
func (o *AssociationsUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this associations update o k response has a 3xx status code
func (o *AssociationsUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this associations update o k response has a 4xx status code
func (o *AssociationsUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this associations update o k response has a 5xx status code
func (o *AssociationsUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this associations update o k response a status code equal to that given
func (o *AssociationsUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the associations update o k response
func (o *AssociationsUpdateOK) Code() int {
	return 200
}

func (o *AssociationsUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /CRM/Associations/{associationId}][%d] associationsUpdateOK %s", 200, payload)
}

func (o *AssociationsUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /CRM/Associations/{associationId}][%d] associationsUpdateOK %s", 200, payload)
}

func (o *AssociationsUpdateOK) GetPayload() *models.Association {
	return o.Payload
}

func (o *AssociationsUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Association)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAssociationsUpdateDefault creates a AssociationsUpdateDefault with default headers values
func NewAssociationsUpdateDefault(code int) *AssociationsUpdateDefault {
	return &AssociationsUpdateDefault{
		_statusCode: code,
	}
}

/*
AssociationsUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type AssociationsUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this associations update default response has a 2xx status code
func (o *AssociationsUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this associations update default response has a 3xx status code
func (o *AssociationsUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this associations update default response has a 4xx status code
func (o *AssociationsUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this associations update default response has a 5xx status code
func (o *AssociationsUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this associations update default response a status code equal to that given
func (o *AssociationsUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the associations update default response
func (o *AssociationsUpdateDefault) Code() int {
	return o._statusCode
}

func (o *AssociationsUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /CRM/Associations/{associationId}][%d] Associations_Update default %s", o._statusCode, payload)
}

func (o *AssociationsUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /CRM/Associations/{associationId}][%d] Associations_Update default %s", o._statusCode, payload)
}

func (o *AssociationsUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *AssociationsUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}