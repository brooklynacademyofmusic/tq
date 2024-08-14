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

// TemplatesGetConstituentInfoReader is a Reader for the TemplatesGetConstituentInfo structure.
type TemplatesGetConstituentInfoReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TemplatesGetConstituentInfoReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewTemplatesGetConstituentInfoOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewTemplatesGetConstituentInfoDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewTemplatesGetConstituentInfoOK creates a TemplatesGetConstituentInfoOK with default headers values
func NewTemplatesGetConstituentInfoOK() *TemplatesGetConstituentInfoOK {
	return &TemplatesGetConstituentInfoOK{}
}

/*
TemplatesGetConstituentInfoOK describes a response with status code 200, with default header values.

OK
*/
type TemplatesGetConstituentInfoOK struct {
	Payload *models.TemplateBody
}

// IsSuccess returns true when this templates get constituent info o k response has a 2xx status code
func (o *TemplatesGetConstituentInfoOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this templates get constituent info o k response has a 3xx status code
func (o *TemplatesGetConstituentInfoOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this templates get constituent info o k response has a 4xx status code
func (o *TemplatesGetConstituentInfoOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this templates get constituent info o k response has a 5xx status code
func (o *TemplatesGetConstituentInfoOK) IsServerError() bool {
	return false
}

// IsCode returns true when this templates get constituent info o k response a status code equal to that given
func (o *TemplatesGetConstituentInfoOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the templates get constituent info o k response
func (o *TemplatesGetConstituentInfoOK) Code() int {
	return 200
}

func (o *TemplatesGetConstituentInfoOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Templates/{templateId}/Constituent/{constituentId}/Info][%d] templatesGetConstituentInfoOK %s", 200, payload)
}

func (o *TemplatesGetConstituentInfoOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Templates/{templateId}/Constituent/{constituentId}/Info][%d] templatesGetConstituentInfoOK %s", 200, payload)
}

func (o *TemplatesGetConstituentInfoOK) GetPayload() *models.TemplateBody {
	return o.Payload
}

func (o *TemplatesGetConstituentInfoOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.TemplateBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTemplatesGetConstituentInfoDefault creates a TemplatesGetConstituentInfoDefault with default headers values
func NewTemplatesGetConstituentInfoDefault(code int) *TemplatesGetConstituentInfoDefault {
	return &TemplatesGetConstituentInfoDefault{
		_statusCode: code,
	}
}

/*
TemplatesGetConstituentInfoDefault describes a response with status code -1, with default header values.

Error
*/
type TemplatesGetConstituentInfoDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this templates get constituent info default response has a 2xx status code
func (o *TemplatesGetConstituentInfoDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this templates get constituent info default response has a 3xx status code
func (o *TemplatesGetConstituentInfoDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this templates get constituent info default response has a 4xx status code
func (o *TemplatesGetConstituentInfoDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this templates get constituent info default response has a 5xx status code
func (o *TemplatesGetConstituentInfoDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this templates get constituent info default response a status code equal to that given
func (o *TemplatesGetConstituentInfoDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the templates get constituent info default response
func (o *TemplatesGetConstituentInfoDefault) Code() int {
	return o._statusCode
}

func (o *TemplatesGetConstituentInfoDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Templates/{templateId}/Constituent/{constituentId}/Info][%d] Templates_GetConstituentInfo default %s", o._statusCode, payload)
}

func (o *TemplatesGetConstituentInfoDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Templates/{templateId}/Constituent/{constituentId}/Info][%d] Templates_GetConstituentInfo default %s", o._statusCode, payload)
}

func (o *TemplatesGetConstituentInfoDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *TemplatesGetConstituentInfoDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}