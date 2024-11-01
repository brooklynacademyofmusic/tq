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

// OrganizationsGetReader is a Reader for the OrganizationsGet structure.
type OrganizationsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *OrganizationsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewOrganizationsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewOrganizationsGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewOrganizationsGetOK creates a OrganizationsGetOK with default headers values
func NewOrganizationsGetOK() *OrganizationsGetOK {
	return &OrganizationsGetOK{}
}

/*
OrganizationsGetOK describes a response with status code 200, with default header values.

OK
*/
type OrganizationsGetOK struct {
	Payload *models.Organization
}

// IsSuccess returns true when this organizations get o k response has a 2xx status code
func (o *OrganizationsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this organizations get o k response has a 3xx status code
func (o *OrganizationsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this organizations get o k response has a 4xx status code
func (o *OrganizationsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this organizations get o k response has a 5xx status code
func (o *OrganizationsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this organizations get o k response a status code equal to that given
func (o *OrganizationsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the organizations get o k response
func (o *OrganizationsGetOK) Code() int {
	return 200
}

func (o *OrganizationsGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Organizations/{id}][%d] organizationsGetOK %s", 200, payload)
}

func (o *OrganizationsGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Organizations/{id}][%d] organizationsGetOK %s", 200, payload)
}

func (o *OrganizationsGetOK) GetPayload() *models.Organization {
	return o.Payload
}

func (o *OrganizationsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Organization)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewOrganizationsGetDefault creates a OrganizationsGetDefault with default headers values
func NewOrganizationsGetDefault(code int) *OrganizationsGetDefault {
	return &OrganizationsGetDefault{
		_statusCode: code,
	}
}

/*
OrganizationsGetDefault describes a response with status code -1, with default header values.

Error
*/
type OrganizationsGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this organizations get default response has a 2xx status code
func (o *OrganizationsGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this organizations get default response has a 3xx status code
func (o *OrganizationsGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this organizations get default response has a 4xx status code
func (o *OrganizationsGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this organizations get default response has a 5xx status code
func (o *OrganizationsGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this organizations get default response a status code equal to that given
func (o *OrganizationsGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the organizations get default response
func (o *OrganizationsGetDefault) Code() int {
	return o._statusCode
}

func (o *OrganizationsGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Organizations/{id}][%d] Organizations_Get default %s", o._statusCode, payload)
}

func (o *OrganizationsGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Organizations/{id}][%d] Organizations_Get default %s", o._statusCode, payload)
}

func (o *OrganizationsGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *OrganizationsGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}