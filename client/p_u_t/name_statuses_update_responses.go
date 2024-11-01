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

// NameStatusesUpdateReader is a Reader for the NameStatusesUpdate structure.
type NameStatusesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *NameStatusesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewNameStatusesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewNameStatusesUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewNameStatusesUpdateOK creates a NameStatusesUpdateOK with default headers values
func NewNameStatusesUpdateOK() *NameStatusesUpdateOK {
	return &NameStatusesUpdateOK{}
}

/*
NameStatusesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type NameStatusesUpdateOK struct {
	Payload *models.NameStatus
}

// IsSuccess returns true when this name statuses update o k response has a 2xx status code
func (o *NameStatusesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this name statuses update o k response has a 3xx status code
func (o *NameStatusesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this name statuses update o k response has a 4xx status code
func (o *NameStatusesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this name statuses update o k response has a 5xx status code
func (o *NameStatusesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this name statuses update o k response a status code equal to that given
func (o *NameStatusesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the name statuses update o k response
func (o *NameStatusesUpdateOK) Code() int {
	return 200
}

func (o *NameStatusesUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/NameStatuses/{id}][%d] nameStatusesUpdateOK %s", 200, payload)
}

func (o *NameStatusesUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/NameStatuses/{id}][%d] nameStatusesUpdateOK %s", 200, payload)
}

func (o *NameStatusesUpdateOK) GetPayload() *models.NameStatus {
	return o.Payload
}

func (o *NameStatusesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.NameStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewNameStatusesUpdateDefault creates a NameStatusesUpdateDefault with default headers values
func NewNameStatusesUpdateDefault(code int) *NameStatusesUpdateDefault {
	return &NameStatusesUpdateDefault{
		_statusCode: code,
	}
}

/*
NameStatusesUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type NameStatusesUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this name statuses update default response has a 2xx status code
func (o *NameStatusesUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this name statuses update default response has a 3xx status code
func (o *NameStatusesUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this name statuses update default response has a 4xx status code
func (o *NameStatusesUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this name statuses update default response has a 5xx status code
func (o *NameStatusesUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this name statuses update default response a status code equal to that given
func (o *NameStatusesUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the name statuses update default response
func (o *NameStatusesUpdateDefault) Code() int {
	return o._statusCode
}

func (o *NameStatusesUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/NameStatuses/{id}][%d] NameStatuses_Update default %s", o._statusCode, payload)
}

func (o *NameStatusesUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/NameStatuses/{id}][%d] NameStatuses_Update default %s", o._statusCode, payload)
}

func (o *NameStatusesUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *NameStatusesUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}