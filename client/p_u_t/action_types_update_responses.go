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

// ActionTypesUpdateReader is a Reader for the ActionTypesUpdate structure.
type ActionTypesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ActionTypesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewActionTypesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewActionTypesUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewActionTypesUpdateOK creates a ActionTypesUpdateOK with default headers values
func NewActionTypesUpdateOK() *ActionTypesUpdateOK {
	return &ActionTypesUpdateOK{}
}

/*
ActionTypesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type ActionTypesUpdateOK struct {
	Payload *models.ActionType
}

// IsSuccess returns true when this action types update o k response has a 2xx status code
func (o *ActionTypesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this action types update o k response has a 3xx status code
func (o *ActionTypesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this action types update o k response has a 4xx status code
func (o *ActionTypesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this action types update o k response has a 5xx status code
func (o *ActionTypesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this action types update o k response a status code equal to that given
func (o *ActionTypesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the action types update o k response
func (o *ActionTypesUpdateOK) Code() int {
	return 200
}

func (o *ActionTypesUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/ActionTypes/{id}][%d] actionTypesUpdateOK %s", 200, payload)
}

func (o *ActionTypesUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/ActionTypes/{id}][%d] actionTypesUpdateOK %s", 200, payload)
}

func (o *ActionTypesUpdateOK) GetPayload() *models.ActionType {
	return o.Payload
}

func (o *ActionTypesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActionType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewActionTypesUpdateDefault creates a ActionTypesUpdateDefault with default headers values
func NewActionTypesUpdateDefault(code int) *ActionTypesUpdateDefault {
	return &ActionTypesUpdateDefault{
		_statusCode: code,
	}
}

/*
ActionTypesUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type ActionTypesUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this action types update default response has a 2xx status code
func (o *ActionTypesUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this action types update default response has a 3xx status code
func (o *ActionTypesUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this action types update default response has a 4xx status code
func (o *ActionTypesUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this action types update default response has a 5xx status code
func (o *ActionTypesUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this action types update default response a status code equal to that given
func (o *ActionTypesUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the action types update default response
func (o *ActionTypesUpdateDefault) Code() int {
	return o._statusCode
}

func (o *ActionTypesUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/ActionTypes/{id}][%d] ActionTypes_Update default %s", o._statusCode, payload)
}

func (o *ActionTypesUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/ActionTypes/{id}][%d] ActionTypes_Update default %s", o._statusCode, payload)
}

func (o *ActionTypesUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ActionTypesUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}