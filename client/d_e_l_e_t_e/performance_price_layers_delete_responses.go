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

// PerformancePriceLayersDeleteReader is a Reader for the PerformancePriceLayersDelete structure.
type PerformancePriceLayersDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PerformancePriceLayersDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewPerformancePriceLayersDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPerformancePriceLayersDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPerformancePriceLayersDeleteNoContent creates a PerformancePriceLayersDeleteNoContent with default headers values
func NewPerformancePriceLayersDeleteNoContent() *PerformancePriceLayersDeleteNoContent {
	return &PerformancePriceLayersDeleteNoContent{}
}

/*
PerformancePriceLayersDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type PerformancePriceLayersDeleteNoContent struct {
}

// IsSuccess returns true when this performance price layers delete no content response has a 2xx status code
func (o *PerformancePriceLayersDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this performance price layers delete no content response has a 3xx status code
func (o *PerformancePriceLayersDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this performance price layers delete no content response has a 4xx status code
func (o *PerformancePriceLayersDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this performance price layers delete no content response has a 5xx status code
func (o *PerformancePriceLayersDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this performance price layers delete no content response a status code equal to that given
func (o *PerformancePriceLayersDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the performance price layers delete no content response
func (o *PerformancePriceLayersDeleteNoContent) Code() int {
	return 204
}

func (o *PerformancePriceLayersDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /TXN/PerformancePriceLayers/{performancePriceLayerId}][%d] performancePriceLayersDeleteNoContent", 204)
}

func (o *PerformancePriceLayersDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /TXN/PerformancePriceLayers/{performancePriceLayerId}][%d] performancePriceLayersDeleteNoContent", 204)
}

func (o *PerformancePriceLayersDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPerformancePriceLayersDeleteDefault creates a PerformancePriceLayersDeleteDefault with default headers values
func NewPerformancePriceLayersDeleteDefault(code int) *PerformancePriceLayersDeleteDefault {
	return &PerformancePriceLayersDeleteDefault{
		_statusCode: code,
	}
}

/*
PerformancePriceLayersDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type PerformancePriceLayersDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this performance price layers delete default response has a 2xx status code
func (o *PerformancePriceLayersDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this performance price layers delete default response has a 3xx status code
func (o *PerformancePriceLayersDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this performance price layers delete default response has a 4xx status code
func (o *PerformancePriceLayersDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this performance price layers delete default response has a 5xx status code
func (o *PerformancePriceLayersDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this performance price layers delete default response a status code equal to that given
func (o *PerformancePriceLayersDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the performance price layers delete default response
func (o *PerformancePriceLayersDeleteDefault) Code() int {
	return o._statusCode
}

func (o *PerformancePriceLayersDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/PerformancePriceLayers/{performancePriceLayerId}][%d] PerformancePriceLayers_Delete default %s", o._statusCode, payload)
}

func (o *PerformancePriceLayersDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/PerformancePriceLayers/{performancePriceLayerId}][%d] PerformancePriceLayers_Delete default %s", o._statusCode, payload)
}

func (o *PerformancePriceLayersDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PerformancePriceLayersDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}