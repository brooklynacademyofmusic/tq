// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

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

// ContactPointPurposeMapsDeleteReader is a Reader for the ContactPointPurposeMapsDelete structure.
type ContactPointPurposeMapsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ContactPointPurposeMapsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewContactPointPurposeMapsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewContactPointPurposeMapsDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewContactPointPurposeMapsDeleteNoContent creates a ContactPointPurposeMapsDeleteNoContent with default headers values
func NewContactPointPurposeMapsDeleteNoContent() *ContactPointPurposeMapsDeleteNoContent {
	return &ContactPointPurposeMapsDeleteNoContent{}
}

/*
ContactPointPurposeMapsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type ContactPointPurposeMapsDeleteNoContent struct {
}

// IsSuccess returns true when this contact point purpose maps delete no content response has a 2xx status code
func (o *ContactPointPurposeMapsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this contact point purpose maps delete no content response has a 3xx status code
func (o *ContactPointPurposeMapsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this contact point purpose maps delete no content response has a 4xx status code
func (o *ContactPointPurposeMapsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this contact point purpose maps delete no content response has a 5xx status code
func (o *ContactPointPurposeMapsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this contact point purpose maps delete no content response a status code equal to that given
func (o *ContactPointPurposeMapsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the contact point purpose maps delete no content response
func (o *ContactPointPurposeMapsDeleteNoContent) Code() int {
	return 204
}

func (o *ContactPointPurposeMapsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /CRM/ContactPointPurposeMaps/{contactPointPurposeMapId}][%d] contactPointPurposeMapsDeleteNoContent", 204)
}

func (o *ContactPointPurposeMapsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /CRM/ContactPointPurposeMaps/{contactPointPurposeMapId}][%d] contactPointPurposeMapsDeleteNoContent", 204)
}

func (o *ContactPointPurposeMapsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewContactPointPurposeMapsDeleteDefault creates a ContactPointPurposeMapsDeleteDefault with default headers values
func NewContactPointPurposeMapsDeleteDefault(code int) *ContactPointPurposeMapsDeleteDefault {
	return &ContactPointPurposeMapsDeleteDefault{
		_statusCode: code,
	}
}

/*
ContactPointPurposeMapsDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type ContactPointPurposeMapsDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this contact point purpose maps delete default response has a 2xx status code
func (o *ContactPointPurposeMapsDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this contact point purpose maps delete default response has a 3xx status code
func (o *ContactPointPurposeMapsDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this contact point purpose maps delete default response has a 4xx status code
func (o *ContactPointPurposeMapsDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this contact point purpose maps delete default response has a 5xx status code
func (o *ContactPointPurposeMapsDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this contact point purpose maps delete default response a status code equal to that given
func (o *ContactPointPurposeMapsDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the contact point purpose maps delete default response
func (o *ContactPointPurposeMapsDeleteDefault) Code() int {
	return o._statusCode
}

func (o *ContactPointPurposeMapsDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /CRM/ContactPointPurposeMaps/{contactPointPurposeMapId}][%d] ContactPointPurposeMaps_Delete default %s", o._statusCode, payload)
}

func (o *ContactPointPurposeMapsDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /CRM/ContactPointPurposeMaps/{contactPointPurposeMapId}][%d] ContactPointPurposeMaps_Delete default %s", o._statusCode, payload)
}

func (o *ContactPointPurposeMapsDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ContactPointPurposeMapsDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}