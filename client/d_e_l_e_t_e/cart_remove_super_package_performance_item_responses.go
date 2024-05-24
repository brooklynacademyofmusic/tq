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

// CartRemoveSuperPackagePerformanceItemReader is a Reader for the CartRemoveSuperPackagePerformanceItem structure.
type CartRemoveSuperPackagePerformanceItemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CartRemoveSuperPackagePerformanceItemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewCartRemoveSuperPackagePerformanceItemNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCartRemoveSuperPackagePerformanceItemDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCartRemoveSuperPackagePerformanceItemNoContent creates a CartRemoveSuperPackagePerformanceItemNoContent with default headers values
func NewCartRemoveSuperPackagePerformanceItemNoContent() *CartRemoveSuperPackagePerformanceItemNoContent {
	return &CartRemoveSuperPackagePerformanceItemNoContent{}
}

/*
CartRemoveSuperPackagePerformanceItemNoContent describes a response with status code 204, with default header values.

No Content
*/
type CartRemoveSuperPackagePerformanceItemNoContent struct {
}

// IsSuccess returns true when this cart remove super package performance item no content response has a 2xx status code
func (o *CartRemoveSuperPackagePerformanceItemNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this cart remove super package performance item no content response has a 3xx status code
func (o *CartRemoveSuperPackagePerformanceItemNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cart remove super package performance item no content response has a 4xx status code
func (o *CartRemoveSuperPackagePerformanceItemNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this cart remove super package performance item no content response has a 5xx status code
func (o *CartRemoveSuperPackagePerformanceItemNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this cart remove super package performance item no content response a status code equal to that given
func (o *CartRemoveSuperPackagePerformanceItemNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the cart remove super package performance item no content response
func (o *CartRemoveSuperPackagePerformanceItemNoContent) Code() int {
	return 204
}

func (o *CartRemoveSuperPackagePerformanceItemNoContent) Error() string {
	return fmt.Sprintf("[DELETE /Web/Cart/{sessionKey}/Packages/Super/{superPackageLineItemId}/{subPackageId}/{performanceLineItemId}/{performanceId}][%d] cartRemoveSuperPackagePerformanceItemNoContent", 204)
}

func (o *CartRemoveSuperPackagePerformanceItemNoContent) String() string {
	return fmt.Sprintf("[DELETE /Web/Cart/{sessionKey}/Packages/Super/{superPackageLineItemId}/{subPackageId}/{performanceLineItemId}/{performanceId}][%d] cartRemoveSuperPackagePerformanceItemNoContent", 204)
}

func (o *CartRemoveSuperPackagePerformanceItemNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewCartRemoveSuperPackagePerformanceItemDefault creates a CartRemoveSuperPackagePerformanceItemDefault with default headers values
func NewCartRemoveSuperPackagePerformanceItemDefault(code int) *CartRemoveSuperPackagePerformanceItemDefault {
	return &CartRemoveSuperPackagePerformanceItemDefault{
		_statusCode: code,
	}
}

/*
CartRemoveSuperPackagePerformanceItemDefault describes a response with status code -1, with default header values.

Error
*/
type CartRemoveSuperPackagePerformanceItemDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this cart remove super package performance item default response has a 2xx status code
func (o *CartRemoveSuperPackagePerformanceItemDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this cart remove super package performance item default response has a 3xx status code
func (o *CartRemoveSuperPackagePerformanceItemDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this cart remove super package performance item default response has a 4xx status code
func (o *CartRemoveSuperPackagePerformanceItemDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this cart remove super package performance item default response has a 5xx status code
func (o *CartRemoveSuperPackagePerformanceItemDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this cart remove super package performance item default response a status code equal to that given
func (o *CartRemoveSuperPackagePerformanceItemDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the cart remove super package performance item default response
func (o *CartRemoveSuperPackagePerformanceItemDefault) Code() int {
	return o._statusCode
}

func (o *CartRemoveSuperPackagePerformanceItemDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /Web/Cart/{sessionKey}/Packages/Super/{superPackageLineItemId}/{subPackageId}/{performanceLineItemId}/{performanceId}][%d] Cart_RemoveSuperPackagePerformanceItem default %s", o._statusCode, payload)
}

func (o *CartRemoveSuperPackagePerformanceItemDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /Web/Cart/{sessionKey}/Packages/Super/{superPackageLineItemId}/{subPackageId}/{performanceLineItemId}/{performanceId}][%d] Cart_RemoveSuperPackagePerformanceItem default %s", o._statusCode, payload)
}

func (o *CartRemoveSuperPackagePerformanceItemDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CartRemoveSuperPackagePerformanceItemDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
