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

// ConstituenciesGetAllReader is a Reader for the ConstituenciesGetAll structure.
type ConstituenciesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ConstituenciesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewConstituenciesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewConstituenciesGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewConstituenciesGetAllOK creates a ConstituenciesGetAllOK with default headers values
func NewConstituenciesGetAllOK() *ConstituenciesGetAllOK {
	return &ConstituenciesGetAllOK{}
}

/*
ConstituenciesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type ConstituenciesGetAllOK struct {
	Payload []*models.Constituency
}

// IsSuccess returns true when this constituencies get all o k response has a 2xx status code
func (o *ConstituenciesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this constituencies get all o k response has a 3xx status code
func (o *ConstituenciesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this constituencies get all o k response has a 4xx status code
func (o *ConstituenciesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this constituencies get all o k response has a 5xx status code
func (o *ConstituenciesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this constituencies get all o k response a status code equal to that given
func (o *ConstituenciesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the constituencies get all o k response
func (o *ConstituenciesGetAllOK) Code() int {
	return 200
}

func (o *ConstituenciesGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/Constituencies][%d] constituenciesGetAllOK %s", 200, payload)
}

func (o *ConstituenciesGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/Constituencies][%d] constituenciesGetAllOK %s", 200, payload)
}

func (o *ConstituenciesGetAllOK) GetPayload() []*models.Constituency {
	return o.Payload
}

func (o *ConstituenciesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewConstituenciesGetAllDefault creates a ConstituenciesGetAllDefault with default headers values
func NewConstituenciesGetAllDefault(code int) *ConstituenciesGetAllDefault {
	return &ConstituenciesGetAllDefault{
		_statusCode: code,
	}
}

/*
ConstituenciesGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type ConstituenciesGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this constituencies get all default response has a 2xx status code
func (o *ConstituenciesGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this constituencies get all default response has a 3xx status code
func (o *ConstituenciesGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this constituencies get all default response has a 4xx status code
func (o *ConstituenciesGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this constituencies get all default response has a 5xx status code
func (o *ConstituenciesGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this constituencies get all default response a status code equal to that given
func (o *ConstituenciesGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the constituencies get all default response
func (o *ConstituenciesGetAllDefault) Code() int {
	return o._statusCode
}

func (o *ConstituenciesGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/Constituencies][%d] Constituencies_GetAll default %s", o._statusCode, payload)
}

func (o *ConstituenciesGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /CRM/Constituencies][%d] Constituencies_GetAll default %s", o._statusCode, payload)
}

func (o *ConstituenciesGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ConstituenciesGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
