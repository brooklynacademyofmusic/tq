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

// PerformancesCopyReader is a Reader for the PerformancesCopy structure.
type PerformancesCopyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PerformancesCopyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewPerformancesCopyNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPerformancesCopyDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPerformancesCopyNoContent creates a PerformancesCopyNoContent with default headers values
func NewPerformancesCopyNoContent() *PerformancesCopyNoContent {
	return &PerformancesCopyNoContent{}
}

/*
PerformancesCopyNoContent describes a response with status code 204, with default header values.

No Content
*/
type PerformancesCopyNoContent struct {
}

// IsSuccess returns true when this performances copy no content response has a 2xx status code
func (o *PerformancesCopyNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this performances copy no content response has a 3xx status code
func (o *PerformancesCopyNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this performances copy no content response has a 4xx status code
func (o *PerformancesCopyNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this performances copy no content response has a 5xx status code
func (o *PerformancesCopyNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this performances copy no content response a status code equal to that given
func (o *PerformancesCopyNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the performances copy no content response
func (o *PerformancesCopyNoContent) Code() int {
	return 204
}

func (o *PerformancesCopyNoContent) Error() string {
	return fmt.Sprintf("[POST /TXN/Performances/Copy][%d] performancesCopyNoContent", 204)
}

func (o *PerformancesCopyNoContent) String() string {
	return fmt.Sprintf("[POST /TXN/Performances/Copy][%d] performancesCopyNoContent", 204)
}

func (o *PerformancesCopyNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPerformancesCopyDefault creates a PerformancesCopyDefault with default headers values
func NewPerformancesCopyDefault(code int) *PerformancesCopyDefault {
	return &PerformancesCopyDefault{
		_statusCode: code,
	}
}

/*
PerformancesCopyDefault describes a response with status code -1, with default header values.

Error
*/
type PerformancesCopyDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this performances copy default response has a 2xx status code
func (o *PerformancesCopyDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this performances copy default response has a 3xx status code
func (o *PerformancesCopyDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this performances copy default response has a 4xx status code
func (o *PerformancesCopyDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this performances copy default response has a 5xx status code
func (o *PerformancesCopyDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this performances copy default response a status code equal to that given
func (o *PerformancesCopyDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the performances copy default response
func (o *PerformancesCopyDefault) Code() int {
	return o._statusCode
}

func (o *PerformancesCopyDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/Performances/Copy][%d] Performances_Copy default %s", o._statusCode, payload)
}

func (o *PerformancesCopyDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/Performances/Copy][%d] Performances_Copy default %s", o._statusCode, payload)
}

func (o *PerformancesCopyDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PerformancesCopyDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}