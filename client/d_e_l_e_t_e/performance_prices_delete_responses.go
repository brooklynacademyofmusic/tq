// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

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

// PerformancePricesDeleteReader is a Reader for the PerformancePricesDelete structure.
type PerformancePricesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PerformancePricesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewPerformancePricesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPerformancePricesDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPerformancePricesDeleteNoContent creates a PerformancePricesDeleteNoContent with default headers values
func NewPerformancePricesDeleteNoContent() *PerformancePricesDeleteNoContent {
	return &PerformancePricesDeleteNoContent{}
}

/*
PerformancePricesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type PerformancePricesDeleteNoContent struct {
}

// IsSuccess returns true when this performance prices delete no content response has a 2xx status code
func (o *PerformancePricesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this performance prices delete no content response has a 3xx status code
func (o *PerformancePricesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this performance prices delete no content response has a 4xx status code
func (o *PerformancePricesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this performance prices delete no content response has a 5xx status code
func (o *PerformancePricesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this performance prices delete no content response a status code equal to that given
func (o *PerformancePricesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the performance prices delete no content response
func (o *PerformancePricesDeleteNoContent) Code() int {
	return 204
}

func (o *PerformancePricesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /TXN/PerformancePrices/{performancePriceId}][%d] performancePricesDeleteNoContent", 204)
}

func (o *PerformancePricesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /TXN/PerformancePrices/{performancePriceId}][%d] performancePricesDeleteNoContent", 204)
}

func (o *PerformancePricesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPerformancePricesDeleteDefault creates a PerformancePricesDeleteDefault with default headers values
func NewPerformancePricesDeleteDefault(code int) *PerformancePricesDeleteDefault {
	return &PerformancePricesDeleteDefault{
		_statusCode: code,
	}
}

/*
PerformancePricesDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type PerformancePricesDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this performance prices delete default response has a 2xx status code
func (o *PerformancePricesDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this performance prices delete default response has a 3xx status code
func (o *PerformancePricesDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this performance prices delete default response has a 4xx status code
func (o *PerformancePricesDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this performance prices delete default response has a 5xx status code
func (o *PerformancePricesDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this performance prices delete default response a status code equal to that given
func (o *PerformancePricesDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the performance prices delete default response
func (o *PerformancePricesDeleteDefault) Code() int {
	return o._statusCode
}

func (o *PerformancePricesDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/PerformancePrices/{performancePriceId}][%d] PerformancePrices_Delete default %s", o._statusCode, payload)
}

func (o *PerformancePricesDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/PerformancePrices/{performancePriceId}][%d] PerformancePrices_Delete default %s", o._statusCode, payload)
}

func (o *PerformancePricesDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PerformancePricesDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
