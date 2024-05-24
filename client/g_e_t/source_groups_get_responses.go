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

// SourceGroupsGetReader is a Reader for the SourceGroupsGet structure.
type SourceGroupsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SourceGroupsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSourceGroupsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSourceGroupsGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSourceGroupsGetOK creates a SourceGroupsGetOK with default headers values
func NewSourceGroupsGetOK() *SourceGroupsGetOK {
	return &SourceGroupsGetOK{}
}

/*
SourceGroupsGetOK describes a response with status code 200, with default header values.

OK
*/
type SourceGroupsGetOK struct {
	Payload *models.SourceGroup
}

// IsSuccess returns true when this source groups get o k response has a 2xx status code
func (o *SourceGroupsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this source groups get o k response has a 3xx status code
func (o *SourceGroupsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this source groups get o k response has a 4xx status code
func (o *SourceGroupsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this source groups get o k response has a 5xx status code
func (o *SourceGroupsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this source groups get o k response a status code equal to that given
func (o *SourceGroupsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the source groups get o k response
func (o *SourceGroupsGetOK) Code() int {
	return 200
}

func (o *SourceGroupsGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SourceGroups/{id}][%d] sourceGroupsGetOK %s", 200, payload)
}

func (o *SourceGroupsGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SourceGroups/{id}][%d] sourceGroupsGetOK %s", 200, payload)
}

func (o *SourceGroupsGetOK) GetPayload() *models.SourceGroup {
	return o.Payload
}

func (o *SourceGroupsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SourceGroup)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSourceGroupsGetDefault creates a SourceGroupsGetDefault with default headers values
func NewSourceGroupsGetDefault(code int) *SourceGroupsGetDefault {
	return &SourceGroupsGetDefault{
		_statusCode: code,
	}
}

/*
SourceGroupsGetDefault describes a response with status code -1, with default header values.

Error
*/
type SourceGroupsGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this source groups get default response has a 2xx status code
func (o *SourceGroupsGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this source groups get default response has a 3xx status code
func (o *SourceGroupsGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this source groups get default response has a 4xx status code
func (o *SourceGroupsGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this source groups get default response has a 5xx status code
func (o *SourceGroupsGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this source groups get default response a status code equal to that given
func (o *SourceGroupsGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the source groups get default response
func (o *SourceGroupsGetDefault) Code() int {
	return o._statusCode
}

func (o *SourceGroupsGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SourceGroups/{id}][%d] SourceGroups_Get default %s", o._statusCode, payload)
}

func (o *SourceGroupsGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SourceGroups/{id}][%d] SourceGroups_Get default %s", o._statusCode, payload)
}

func (o *SourceGroupsGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SourceGroupsGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
