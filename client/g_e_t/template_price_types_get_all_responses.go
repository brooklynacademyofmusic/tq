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

// TemplatePriceTypesGetAllReader is a Reader for the TemplatePriceTypesGetAll structure.
type TemplatePriceTypesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TemplatePriceTypesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewTemplatePriceTypesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewTemplatePriceTypesGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewTemplatePriceTypesGetAllOK creates a TemplatePriceTypesGetAllOK with default headers values
func NewTemplatePriceTypesGetAllOK() *TemplatePriceTypesGetAllOK {
	return &TemplatePriceTypesGetAllOK{}
}

/*
TemplatePriceTypesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type TemplatePriceTypesGetAllOK struct {
	Payload []*models.TemplatePriceType
}

// IsSuccess returns true when this template price types get all o k response has a 2xx status code
func (o *TemplatePriceTypesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this template price types get all o k response has a 3xx status code
func (o *TemplatePriceTypesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this template price types get all o k response has a 4xx status code
func (o *TemplatePriceTypesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this template price types get all o k response has a 5xx status code
func (o *TemplatePriceTypesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this template price types get all o k response a status code equal to that given
func (o *TemplatePriceTypesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the template price types get all o k response
func (o *TemplatePriceTypesGetAllOK) Code() int {
	return 200
}

func (o *TemplatePriceTypesGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/TemplatePriceTypes][%d] templatePriceTypesGetAllOK %s", 200, payload)
}

func (o *TemplatePriceTypesGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/TemplatePriceTypes][%d] templatePriceTypesGetAllOK %s", 200, payload)
}

func (o *TemplatePriceTypesGetAllOK) GetPayload() []*models.TemplatePriceType {
	return o.Payload
}

func (o *TemplatePriceTypesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTemplatePriceTypesGetAllDefault creates a TemplatePriceTypesGetAllDefault with default headers values
func NewTemplatePriceTypesGetAllDefault(code int) *TemplatePriceTypesGetAllDefault {
	return &TemplatePriceTypesGetAllDefault{
		_statusCode: code,
	}
}

/*
TemplatePriceTypesGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type TemplatePriceTypesGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this template price types get all default response has a 2xx status code
func (o *TemplatePriceTypesGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this template price types get all default response has a 3xx status code
func (o *TemplatePriceTypesGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this template price types get all default response has a 4xx status code
func (o *TemplatePriceTypesGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this template price types get all default response has a 5xx status code
func (o *TemplatePriceTypesGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this template price types get all default response a status code equal to that given
func (o *TemplatePriceTypesGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the template price types get all default response
func (o *TemplatePriceTypesGetAllDefault) Code() int {
	return o._statusCode
}

func (o *TemplatePriceTypesGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/TemplatePriceTypes][%d] TemplatePriceTypes_GetAll default %s", o._statusCode, payload)
}

func (o *TemplatePriceTypesGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/TemplatePriceTypes][%d] TemplatePriceTypes_GetAll default %s", o._statusCode, payload)
}

func (o *TemplatePriceTypesGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *TemplatePriceTypesGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}