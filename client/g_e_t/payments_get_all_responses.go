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

// PaymentsGetAllReader is a Reader for the PaymentsGetAll structure.
type PaymentsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PaymentsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPaymentsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPaymentsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPaymentsGetAllOK creates a PaymentsGetAllOK with default headers values
func NewPaymentsGetAllOK() *PaymentsGetAllOK {
	return &PaymentsGetAllOK{}
}

/*
PaymentsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type PaymentsGetAllOK struct {
	Payload []*models.Payment
}

// IsSuccess returns true when this payments get all o k response has a 2xx status code
func (o *PaymentsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this payments get all o k response has a 3xx status code
func (o *PaymentsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this payments get all o k response has a 4xx status code
func (o *PaymentsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this payments get all o k response has a 5xx status code
func (o *PaymentsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this payments get all o k response a status code equal to that given
func (o *PaymentsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the payments get all o k response
func (o *PaymentsGetAllOK) Code() int {
	return 200
}

func (o *PaymentsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Payments][%d] paymentsGetAllOK %s", 200, payload)
}

func (o *PaymentsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Payments][%d] paymentsGetAllOK %s", 200, payload)
}

func (o *PaymentsGetAllOK) GetPayload() []*models.Payment {
	return o.Payload
}

func (o *PaymentsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPaymentsGetAllDefault creates a PaymentsGetAllDefault with default headers values
func NewPaymentsGetAllDefault(code int) *PaymentsGetAllDefault {
	return &PaymentsGetAllDefault{
		_statusCode: code,
	}
}

/*
PaymentsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type PaymentsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this payments get all default response has a 2xx status code
func (o *PaymentsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this payments get all default response has a 3xx status code
func (o *PaymentsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this payments get all default response has a 4xx status code
func (o *PaymentsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this payments get all default response has a 5xx status code
func (o *PaymentsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this payments get all default response a status code equal to that given
func (o *PaymentsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the payments get all default response
func (o *PaymentsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *PaymentsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Payments][%d] Payments_GetAll default %s", o._statusCode, payload)
}

func (o *PaymentsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Payments][%d] Payments_GetAll default %s", o._statusCode, payload)
}

func (o *PaymentsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PaymentsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
