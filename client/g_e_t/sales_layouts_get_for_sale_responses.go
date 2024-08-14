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

// SalesLayoutsGetForSaleReader is a Reader for the SalesLayoutsGetForSale structure.
type SalesLayoutsGetForSaleReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SalesLayoutsGetForSaleReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSalesLayoutsGetForSaleOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSalesLayoutsGetForSaleDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSalesLayoutsGetForSaleOK creates a SalesLayoutsGetForSaleOK with default headers values
func NewSalesLayoutsGetForSaleOK() *SalesLayoutsGetForSaleOK {
	return &SalesLayoutsGetForSaleOK{}
}

/*
SalesLayoutsGetForSaleOK describes a response with status code 200, with default header values.

OK
*/
type SalesLayoutsGetForSaleOK struct {
	Payload *models.SalesLayout
}

// IsSuccess returns true when this sales layouts get for sale o k response has a 2xx status code
func (o *SalesLayoutsGetForSaleOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this sales layouts get for sale o k response has a 3xx status code
func (o *SalesLayoutsGetForSaleOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this sales layouts get for sale o k response has a 4xx status code
func (o *SalesLayoutsGetForSaleOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this sales layouts get for sale o k response has a 5xx status code
func (o *SalesLayoutsGetForSaleOK) IsServerError() bool {
	return false
}

// IsCode returns true when this sales layouts get for sale o k response a status code equal to that given
func (o *SalesLayoutsGetForSaleOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the sales layouts get for sale o k response
func (o *SalesLayoutsGetForSaleOK) Code() int {
	return 200
}

func (o *SalesLayoutsGetForSaleOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/SalesLayouts/{salesLayoutId}][%d] salesLayoutsGetForSaleOK %s", 200, payload)
}

func (o *SalesLayoutsGetForSaleOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/SalesLayouts/{salesLayoutId}][%d] salesLayoutsGetForSaleOK %s", 200, payload)
}

func (o *SalesLayoutsGetForSaleOK) GetPayload() *models.SalesLayout {
	return o.Payload
}

func (o *SalesLayoutsGetForSaleOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SalesLayout)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSalesLayoutsGetForSaleDefault creates a SalesLayoutsGetForSaleDefault with default headers values
func NewSalesLayoutsGetForSaleDefault(code int) *SalesLayoutsGetForSaleDefault {
	return &SalesLayoutsGetForSaleDefault{
		_statusCode: code,
	}
}

/*
SalesLayoutsGetForSaleDefault describes a response with status code -1, with default header values.

Error
*/
type SalesLayoutsGetForSaleDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this sales layouts get for sale default response has a 2xx status code
func (o *SalesLayoutsGetForSaleDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this sales layouts get for sale default response has a 3xx status code
func (o *SalesLayoutsGetForSaleDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this sales layouts get for sale default response has a 4xx status code
func (o *SalesLayoutsGetForSaleDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this sales layouts get for sale default response has a 5xx status code
func (o *SalesLayoutsGetForSaleDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this sales layouts get for sale default response a status code equal to that given
func (o *SalesLayoutsGetForSaleDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the sales layouts get for sale default response
func (o *SalesLayoutsGetForSaleDefault) Code() int {
	return o._statusCode
}

func (o *SalesLayoutsGetForSaleDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/SalesLayouts/{salesLayoutId}][%d] SalesLayouts_GetForSale default %s", o._statusCode, payload)
}

func (o *SalesLayoutsGetForSaleDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/SalesLayouts/{salesLayoutId}][%d] SalesLayouts_GetForSale default %s", o._statusCode, payload)
}

func (o *SalesLayoutsGetForSaleDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SalesLayoutsGetForSaleDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}