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

// InactiveReasonsGetAllReader is a Reader for the InactiveReasonsGetAll structure.
type InactiveReasonsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *InactiveReasonsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewInactiveReasonsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewInactiveReasonsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewInactiveReasonsGetAllOK creates a InactiveReasonsGetAllOK with default headers values
func NewInactiveReasonsGetAllOK() *InactiveReasonsGetAllOK {
	return &InactiveReasonsGetAllOK{}
}

/*
InactiveReasonsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type InactiveReasonsGetAllOK struct {
	Payload []*models.InactiveReason
}

// IsSuccess returns true when this inactive reasons get all o k response has a 2xx status code
func (o *InactiveReasonsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this inactive reasons get all o k response has a 3xx status code
func (o *InactiveReasonsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this inactive reasons get all o k response has a 4xx status code
func (o *InactiveReasonsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this inactive reasons get all o k response has a 5xx status code
func (o *InactiveReasonsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this inactive reasons get all o k response a status code equal to that given
func (o *InactiveReasonsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the inactive reasons get all o k response
func (o *InactiveReasonsGetAllOK) Code() int {
	return 200
}

func (o *InactiveReasonsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/InactiveReasons][%d] inactiveReasonsGetAllOK %s", 200, payload)
}

func (o *InactiveReasonsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/InactiveReasons][%d] inactiveReasonsGetAllOK %s", 200, payload)
}

func (o *InactiveReasonsGetAllOK) GetPayload() []*models.InactiveReason {
	return o.Payload
}

func (o *InactiveReasonsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewInactiveReasonsGetAllDefault creates a InactiveReasonsGetAllDefault with default headers values
func NewInactiveReasonsGetAllDefault(code int) *InactiveReasonsGetAllDefault {
	return &InactiveReasonsGetAllDefault{
		_statusCode: code,
	}
}

/*
InactiveReasonsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type InactiveReasonsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this inactive reasons get all default response has a 2xx status code
func (o *InactiveReasonsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this inactive reasons get all default response has a 3xx status code
func (o *InactiveReasonsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this inactive reasons get all default response has a 4xx status code
func (o *InactiveReasonsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this inactive reasons get all default response has a 5xx status code
func (o *InactiveReasonsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this inactive reasons get all default response a status code equal to that given
func (o *InactiveReasonsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the inactive reasons get all default response
func (o *InactiveReasonsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *InactiveReasonsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/InactiveReasons][%d] InactiveReasons_GetAll default %s", o._statusCode, payload)
}

func (o *InactiveReasonsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/InactiveReasons][%d] InactiveReasons_GetAll default %s", o._statusCode, payload)
}

func (o *InactiveReasonsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *InactiveReasonsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
