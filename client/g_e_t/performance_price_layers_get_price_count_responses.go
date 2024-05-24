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

// PerformancePriceLayersGetPriceCountReader is a Reader for the PerformancePriceLayersGetPriceCount structure.
type PerformancePriceLayersGetPriceCountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PerformancePriceLayersGetPriceCountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPerformancePriceLayersGetPriceCountOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPerformancePriceLayersGetPriceCountDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPerformancePriceLayersGetPriceCountOK creates a PerformancePriceLayersGetPriceCountOK with default headers values
func NewPerformancePriceLayersGetPriceCountOK() *PerformancePriceLayersGetPriceCountOK {
	return &PerformancePriceLayersGetPriceCountOK{}
}

/*
PerformancePriceLayersGetPriceCountOK describes a response with status code 200, with default header values.

OK
*/
type PerformancePriceLayersGetPriceCountOK struct {
	Payload *models.PerformancePriceCount
}

// IsSuccess returns true when this performance price layers get price count o k response has a 2xx status code
func (o *PerformancePriceLayersGetPriceCountOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this performance price layers get price count o k response has a 3xx status code
func (o *PerformancePriceLayersGetPriceCountOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this performance price layers get price count o k response has a 4xx status code
func (o *PerformancePriceLayersGetPriceCountOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this performance price layers get price count o k response has a 5xx status code
func (o *PerformancePriceLayersGetPriceCountOK) IsServerError() bool {
	return false
}

// IsCode returns true when this performance price layers get price count o k response a status code equal to that given
func (o *PerformancePriceLayersGetPriceCountOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the performance price layers get price count o k response
func (o *PerformancePriceLayersGetPriceCountOK) Code() int {
	return 200
}

func (o *PerformancePriceLayersGetPriceCountOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PerformancePriceLayers/PriceCount][%d] performancePriceLayersGetPriceCountOK %s", 200, payload)
}

func (o *PerformancePriceLayersGetPriceCountOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PerformancePriceLayers/PriceCount][%d] performancePriceLayersGetPriceCountOK %s", 200, payload)
}

func (o *PerformancePriceLayersGetPriceCountOK) GetPayload() *models.PerformancePriceCount {
	return o.Payload
}

func (o *PerformancePriceLayersGetPriceCountOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PerformancePriceCount)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPerformancePriceLayersGetPriceCountDefault creates a PerformancePriceLayersGetPriceCountDefault with default headers values
func NewPerformancePriceLayersGetPriceCountDefault(code int) *PerformancePriceLayersGetPriceCountDefault {
	return &PerformancePriceLayersGetPriceCountDefault{
		_statusCode: code,
	}
}

/*
PerformancePriceLayersGetPriceCountDefault describes a response with status code -1, with default header values.

Error
*/
type PerformancePriceLayersGetPriceCountDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this performance price layers get price count default response has a 2xx status code
func (o *PerformancePriceLayersGetPriceCountDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this performance price layers get price count default response has a 3xx status code
func (o *PerformancePriceLayersGetPriceCountDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this performance price layers get price count default response has a 4xx status code
func (o *PerformancePriceLayersGetPriceCountDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this performance price layers get price count default response has a 5xx status code
func (o *PerformancePriceLayersGetPriceCountDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this performance price layers get price count default response a status code equal to that given
func (o *PerformancePriceLayersGetPriceCountDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the performance price layers get price count default response
func (o *PerformancePriceLayersGetPriceCountDefault) Code() int {
	return o._statusCode
}

func (o *PerformancePriceLayersGetPriceCountDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PerformancePriceLayers/PriceCount][%d] PerformancePriceLayers_GetPriceCount default %s", o._statusCode, payload)
}

func (o *PerformancePriceLayersGetPriceCountDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/PerformancePriceLayers/PriceCount][%d] PerformancePriceLayers_GetPriceCount default %s", o._statusCode, payload)
}

func (o *PerformancePriceLayersGetPriceCountDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PerformancePriceLayersGetPriceCountDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
