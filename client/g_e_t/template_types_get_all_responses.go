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

// TemplateTypesGetAllReader is a Reader for the TemplateTypesGetAll structure.
type TemplateTypesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TemplateTypesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewTemplateTypesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewTemplateTypesGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewTemplateTypesGetAllOK creates a TemplateTypesGetAllOK with default headers values
func NewTemplateTypesGetAllOK() *TemplateTypesGetAllOK {
	return &TemplateTypesGetAllOK{}
}

/*
TemplateTypesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type TemplateTypesGetAllOK struct {
	Payload []*models.TemplateType
}

// IsSuccess returns true when this template types get all o k response has a 2xx status code
func (o *TemplateTypesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this template types get all o k response has a 3xx status code
func (o *TemplateTypesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this template types get all o k response has a 4xx status code
func (o *TemplateTypesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this template types get all o k response has a 5xx status code
func (o *TemplateTypesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this template types get all o k response a status code equal to that given
func (o *TemplateTypesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the template types get all o k response
func (o *TemplateTypesGetAllOK) Code() int {
	return 200
}

func (o *TemplateTypesGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/TemplateTypes][%d] templateTypesGetAllOK %s", 200, payload)
}

func (o *TemplateTypesGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/TemplateTypes][%d] templateTypesGetAllOK %s", 200, payload)
}

func (o *TemplateTypesGetAllOK) GetPayload() []*models.TemplateType {
	return o.Payload
}

func (o *TemplateTypesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTemplateTypesGetAllDefault creates a TemplateTypesGetAllDefault with default headers values
func NewTemplateTypesGetAllDefault(code int) *TemplateTypesGetAllDefault {
	return &TemplateTypesGetAllDefault{
		_statusCode: code,
	}
}

/*
TemplateTypesGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type TemplateTypesGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this template types get all default response has a 2xx status code
func (o *TemplateTypesGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this template types get all default response has a 3xx status code
func (o *TemplateTypesGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this template types get all default response has a 4xx status code
func (o *TemplateTypesGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this template types get all default response has a 5xx status code
func (o *TemplateTypesGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this template types get all default response a status code equal to that given
func (o *TemplateTypesGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the template types get all default response
func (o *TemplateTypesGetAllDefault) Code() int {
	return o._statusCode
}

func (o *TemplateTypesGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/TemplateTypes][%d] TemplateTypes_GetAll default %s", o._statusCode, payload)
}

func (o *TemplateTypesGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/TemplateTypes][%d] TemplateTypes_GetAll default %s", o._statusCode, payload)
}

func (o *TemplateTypesGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *TemplateTypesGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}