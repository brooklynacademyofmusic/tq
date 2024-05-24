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

// AssociationTypesGetAllReader is a Reader for the AssociationTypesGetAll structure.
type AssociationTypesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AssociationTypesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAssociationTypesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewAssociationTypesGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewAssociationTypesGetAllOK creates a AssociationTypesGetAllOK with default headers values
func NewAssociationTypesGetAllOK() *AssociationTypesGetAllOK {
	return &AssociationTypesGetAllOK{}
}

/*
AssociationTypesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type AssociationTypesGetAllOK struct {
	Payload []*models.AssociationType
}

// IsSuccess returns true when this association types get all o k response has a 2xx status code
func (o *AssociationTypesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this association types get all o k response has a 3xx status code
func (o *AssociationTypesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this association types get all o k response has a 4xx status code
func (o *AssociationTypesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this association types get all o k response has a 5xx status code
func (o *AssociationTypesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this association types get all o k response a status code equal to that given
func (o *AssociationTypesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the association types get all o k response
func (o *AssociationTypesGetAllOK) Code() int {
	return 200
}

func (o *AssociationTypesGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/AssociationTypes][%d] associationTypesGetAllOK %s", 200, payload)
}

func (o *AssociationTypesGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/AssociationTypes][%d] associationTypesGetAllOK %s", 200, payload)
}

func (o *AssociationTypesGetAllOK) GetPayload() []*models.AssociationType {
	return o.Payload
}

func (o *AssociationTypesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAssociationTypesGetAllDefault creates a AssociationTypesGetAllDefault with default headers values
func NewAssociationTypesGetAllDefault(code int) *AssociationTypesGetAllDefault {
	return &AssociationTypesGetAllDefault{
		_statusCode: code,
	}
}

/*
AssociationTypesGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type AssociationTypesGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this association types get all default response has a 2xx status code
func (o *AssociationTypesGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this association types get all default response has a 3xx status code
func (o *AssociationTypesGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this association types get all default response has a 4xx status code
func (o *AssociationTypesGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this association types get all default response has a 5xx status code
func (o *AssociationTypesGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this association types get all default response a status code equal to that given
func (o *AssociationTypesGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the association types get all default response
func (o *AssociationTypesGetAllDefault) Code() int {
	return o._statusCode
}

func (o *AssociationTypesGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/AssociationTypes][%d] AssociationTypes_GetAll default %s", o._statusCode, payload)
}

func (o *AssociationTypesGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/AssociationTypes][%d] AssociationTypes_GetAll default %s", o._statusCode, payload)
}

func (o *AssociationTypesGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *AssociationTypesGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
