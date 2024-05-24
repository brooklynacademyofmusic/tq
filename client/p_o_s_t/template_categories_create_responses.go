// Code generated by go-swagger; DO NOT EDIT.

package p_o_s_t

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

// TemplateCategoriesCreateReader is a Reader for the TemplateCategoriesCreate structure.
type TemplateCategoriesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TemplateCategoriesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewTemplateCategoriesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewTemplateCategoriesCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewTemplateCategoriesCreateOK creates a TemplateCategoriesCreateOK with default headers values
func NewTemplateCategoriesCreateOK() *TemplateCategoriesCreateOK {
	return &TemplateCategoriesCreateOK{}
}

/*
TemplateCategoriesCreateOK describes a response with status code 200, with default header values.

OK
*/
type TemplateCategoriesCreateOK struct {
	Payload *models.TemplateCategory
}

// IsSuccess returns true when this template categories create o k response has a 2xx status code
func (o *TemplateCategoriesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this template categories create o k response has a 3xx status code
func (o *TemplateCategoriesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this template categories create o k response has a 4xx status code
func (o *TemplateCategoriesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this template categories create o k response has a 5xx status code
func (o *TemplateCategoriesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this template categories create o k response a status code equal to that given
func (o *TemplateCategoriesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the template categories create o k response
func (o *TemplateCategoriesCreateOK) Code() int {
	return 200
}

func (o *TemplateCategoriesCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/TemplateCategories][%d] templateCategoriesCreateOK %s", 200, payload)
}

func (o *TemplateCategoriesCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/TemplateCategories][%d] templateCategoriesCreateOK %s", 200, payload)
}

func (o *TemplateCategoriesCreateOK) GetPayload() *models.TemplateCategory {
	return o.Payload
}

func (o *TemplateCategoriesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.TemplateCategory)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTemplateCategoriesCreateDefault creates a TemplateCategoriesCreateDefault with default headers values
func NewTemplateCategoriesCreateDefault(code int) *TemplateCategoriesCreateDefault {
	return &TemplateCategoriesCreateDefault{
		_statusCode: code,
	}
}

/*
TemplateCategoriesCreateDefault describes a response with status code -1, with default header values.

Error
*/
type TemplateCategoriesCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this template categories create default response has a 2xx status code
func (o *TemplateCategoriesCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this template categories create default response has a 3xx status code
func (o *TemplateCategoriesCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this template categories create default response has a 4xx status code
func (o *TemplateCategoriesCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this template categories create default response has a 5xx status code
func (o *TemplateCategoriesCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this template categories create default response a status code equal to that given
func (o *TemplateCategoriesCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the template categories create default response
func (o *TemplateCategoriesCreateDefault) Code() int {
	return o._statusCode
}

func (o *TemplateCategoriesCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/TemplateCategories][%d] TemplateCategories_Create default %s", o._statusCode, payload)
}

func (o *TemplateCategoriesCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/TemplateCategories][%d] TemplateCategories_Create default %s", o._statusCode, payload)
}

func (o *TemplateCategoriesCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *TemplateCategoriesCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
