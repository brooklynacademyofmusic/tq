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

// PerformancePriceTypesDeleteAllReader is a Reader for the PerformancePriceTypesDeleteAll structure.
type PerformancePriceTypesDeleteAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PerformancePriceTypesDeleteAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewPerformancePriceTypesDeleteAllNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPerformancePriceTypesDeleteAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPerformancePriceTypesDeleteAllNoContent creates a PerformancePriceTypesDeleteAllNoContent with default headers values
func NewPerformancePriceTypesDeleteAllNoContent() *PerformancePriceTypesDeleteAllNoContent {
	return &PerformancePriceTypesDeleteAllNoContent{}
}

/*
PerformancePriceTypesDeleteAllNoContent describes a response with status code 204, with default header values.

No Content
*/
type PerformancePriceTypesDeleteAllNoContent struct {
}

// IsSuccess returns true when this performance price types delete all no content response has a 2xx status code
func (o *PerformancePriceTypesDeleteAllNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this performance price types delete all no content response has a 3xx status code
func (o *PerformancePriceTypesDeleteAllNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this performance price types delete all no content response has a 4xx status code
func (o *PerformancePriceTypesDeleteAllNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this performance price types delete all no content response has a 5xx status code
func (o *PerformancePriceTypesDeleteAllNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this performance price types delete all no content response a status code equal to that given
func (o *PerformancePriceTypesDeleteAllNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the performance price types delete all no content response
func (o *PerformancePriceTypesDeleteAllNoContent) Code() int {
	return 204
}

func (o *PerformancePriceTypesDeleteAllNoContent) Error() string {
	return fmt.Sprintf("[DELETE /TXN/PerformancePriceTypes][%d] performancePriceTypesDeleteAllNoContent", 204)
}

func (o *PerformancePriceTypesDeleteAllNoContent) String() string {
	return fmt.Sprintf("[DELETE /TXN/PerformancePriceTypes][%d] performancePriceTypesDeleteAllNoContent", 204)
}

func (o *PerformancePriceTypesDeleteAllNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPerformancePriceTypesDeleteAllDefault creates a PerformancePriceTypesDeleteAllDefault with default headers values
func NewPerformancePriceTypesDeleteAllDefault(code int) *PerformancePriceTypesDeleteAllDefault {
	return &PerformancePriceTypesDeleteAllDefault{
		_statusCode: code,
	}
}

/*
PerformancePriceTypesDeleteAllDefault describes a response with status code -1, with default header values.

Error
*/
type PerformancePriceTypesDeleteAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this performance price types delete all default response has a 2xx status code
func (o *PerformancePriceTypesDeleteAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this performance price types delete all default response has a 3xx status code
func (o *PerformancePriceTypesDeleteAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this performance price types delete all default response has a 4xx status code
func (o *PerformancePriceTypesDeleteAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this performance price types delete all default response has a 5xx status code
func (o *PerformancePriceTypesDeleteAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this performance price types delete all default response a status code equal to that given
func (o *PerformancePriceTypesDeleteAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the performance price types delete all default response
func (o *PerformancePriceTypesDeleteAllDefault) Code() int {
	return o._statusCode
}

func (o *PerformancePriceTypesDeleteAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/PerformancePriceTypes][%d] PerformancePriceTypes_DeleteAll default %s", o._statusCode, payload)
}

func (o *PerformancePriceTypesDeleteAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/PerformancePriceTypes][%d] PerformancePriceTypes_DeleteAll default %s", o._statusCode, payload)
}

func (o *PerformancePriceTypesDeleteAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PerformancePriceTypesDeleteAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
