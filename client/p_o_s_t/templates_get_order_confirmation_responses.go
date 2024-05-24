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

// TemplatesGetOrderConfirmationReader is a Reader for the TemplatesGetOrderConfirmation structure.
type TemplatesGetOrderConfirmationReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TemplatesGetOrderConfirmationReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewTemplatesGetOrderConfirmationOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewTemplatesGetOrderConfirmationDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewTemplatesGetOrderConfirmationOK creates a TemplatesGetOrderConfirmationOK with default headers values
func NewTemplatesGetOrderConfirmationOK() *TemplatesGetOrderConfirmationOK {
	return &TemplatesGetOrderConfirmationOK{}
}

/*
TemplatesGetOrderConfirmationOK describes a response with status code 200, with default header values.

OK
*/
type TemplatesGetOrderConfirmationOK struct {
	Payload *models.TemplateBody
}

// IsSuccess returns true when this templates get order confirmation o k response has a 2xx status code
func (o *TemplatesGetOrderConfirmationOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this templates get order confirmation o k response has a 3xx status code
func (o *TemplatesGetOrderConfirmationOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this templates get order confirmation o k response has a 4xx status code
func (o *TemplatesGetOrderConfirmationOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this templates get order confirmation o k response has a 5xx status code
func (o *TemplatesGetOrderConfirmationOK) IsServerError() bool {
	return false
}

// IsCode returns true when this templates get order confirmation o k response a status code equal to that given
func (o *TemplatesGetOrderConfirmationOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the templates get order confirmation o k response
func (o *TemplatesGetOrderConfirmationOK) Code() int {
	return 200
}

func (o *TemplatesGetOrderConfirmationOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Templates/{templateId}/Order/{orderId}/Confirmation][%d] templatesGetOrderConfirmationOK %s", 200, payload)
}

func (o *TemplatesGetOrderConfirmationOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Templates/{templateId}/Order/{orderId}/Confirmation][%d] templatesGetOrderConfirmationOK %s", 200, payload)
}

func (o *TemplatesGetOrderConfirmationOK) GetPayload() *models.TemplateBody {
	return o.Payload
}

func (o *TemplatesGetOrderConfirmationOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.TemplateBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTemplatesGetOrderConfirmationDefault creates a TemplatesGetOrderConfirmationDefault with default headers values
func NewTemplatesGetOrderConfirmationDefault(code int) *TemplatesGetOrderConfirmationDefault {
	return &TemplatesGetOrderConfirmationDefault{
		_statusCode: code,
	}
}

/*
TemplatesGetOrderConfirmationDefault describes a response with status code -1, with default header values.

Error
*/
type TemplatesGetOrderConfirmationDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this templates get order confirmation default response has a 2xx status code
func (o *TemplatesGetOrderConfirmationDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this templates get order confirmation default response has a 3xx status code
func (o *TemplatesGetOrderConfirmationDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this templates get order confirmation default response has a 4xx status code
func (o *TemplatesGetOrderConfirmationDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this templates get order confirmation default response has a 5xx status code
func (o *TemplatesGetOrderConfirmationDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this templates get order confirmation default response a status code equal to that given
func (o *TemplatesGetOrderConfirmationDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the templates get order confirmation default response
func (o *TemplatesGetOrderConfirmationDefault) Code() int {
	return o._statusCode
}

func (o *TemplatesGetOrderConfirmationDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Templates/{templateId}/Order/{orderId}/Confirmation][%d] Templates_GetOrderConfirmation default %s", o._statusCode, payload)
}

func (o *TemplatesGetOrderConfirmationDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Templates/{templateId}/Order/{orderId}/Confirmation][%d] Templates_GetOrderConfirmation default %s", o._statusCode, payload)
}

func (o *TemplatesGetOrderConfirmationDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *TemplatesGetOrderConfirmationDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
