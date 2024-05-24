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

// ContactPointPurposeMapsUpdateReader is a Reader for the ContactPointPurposeMapsUpdate structure.
type ContactPointPurposeMapsUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ContactPointPurposeMapsUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewContactPointPurposeMapsUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewContactPointPurposeMapsUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewContactPointPurposeMapsUpdateOK creates a ContactPointPurposeMapsUpdateOK with default headers values
func NewContactPointPurposeMapsUpdateOK() *ContactPointPurposeMapsUpdateOK {
	return &ContactPointPurposeMapsUpdateOK{}
}

/*
ContactPointPurposeMapsUpdateOK describes a response with status code 200, with default header values.

OK
*/
type ContactPointPurposeMapsUpdateOK struct {
	Payload *models.ContactPointPurposeMap
}

// IsSuccess returns true when this contact point purpose maps update o k response has a 2xx status code
func (o *ContactPointPurposeMapsUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this contact point purpose maps update o k response has a 3xx status code
func (o *ContactPointPurposeMapsUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this contact point purpose maps update o k response has a 4xx status code
func (o *ContactPointPurposeMapsUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this contact point purpose maps update o k response has a 5xx status code
func (o *ContactPointPurposeMapsUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this contact point purpose maps update o k response a status code equal to that given
func (o *ContactPointPurposeMapsUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the contact point purpose maps update o k response
func (o *ContactPointPurposeMapsUpdateOK) Code() int {
	return 200
}

func (o *ContactPointPurposeMapsUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /CRM/ContactPointPurposeMaps/{contactPointPurposeMapId}][%d] contactPointPurposeMapsUpdateOK %s", 200, payload)
}

func (o *ContactPointPurposeMapsUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /CRM/ContactPointPurposeMaps/{contactPointPurposeMapId}][%d] contactPointPurposeMapsUpdateOK %s", 200, payload)
}

func (o *ContactPointPurposeMapsUpdateOK) GetPayload() *models.ContactPointPurposeMap {
	return o.Payload
}

func (o *ContactPointPurposeMapsUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ContactPointPurposeMap)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewContactPointPurposeMapsUpdateDefault creates a ContactPointPurposeMapsUpdateDefault with default headers values
func NewContactPointPurposeMapsUpdateDefault(code int) *ContactPointPurposeMapsUpdateDefault {
	return &ContactPointPurposeMapsUpdateDefault{
		_statusCode: code,
	}
}

/*
ContactPointPurposeMapsUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type ContactPointPurposeMapsUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this contact point purpose maps update default response has a 2xx status code
func (o *ContactPointPurposeMapsUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this contact point purpose maps update default response has a 3xx status code
func (o *ContactPointPurposeMapsUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this contact point purpose maps update default response has a 4xx status code
func (o *ContactPointPurposeMapsUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this contact point purpose maps update default response has a 5xx status code
func (o *ContactPointPurposeMapsUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this contact point purpose maps update default response a status code equal to that given
func (o *ContactPointPurposeMapsUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the contact point purpose maps update default response
func (o *ContactPointPurposeMapsUpdateDefault) Code() int {
	return o._statusCode
}

func (o *ContactPointPurposeMapsUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /CRM/ContactPointPurposeMaps/{contactPointPurposeMapId}][%d] ContactPointPurposeMaps_Update default %s", o._statusCode, payload)
}

func (o *ContactPointPurposeMapsUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /CRM/ContactPointPurposeMaps/{contactPointPurposeMapId}][%d] ContactPointPurposeMaps_Update default %s", o._statusCode, payload)
}

func (o *ContactPointPurposeMapsUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ContactPointPurposeMapsUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
