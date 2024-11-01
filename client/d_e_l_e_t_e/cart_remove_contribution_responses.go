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

// CartRemoveContributionReader is a Reader for the CartRemoveContribution structure.
type CartRemoveContributionReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CartRemoveContributionReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewCartRemoveContributionNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCartRemoveContributionDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCartRemoveContributionNoContent creates a CartRemoveContributionNoContent with default headers values
func NewCartRemoveContributionNoContent() *CartRemoveContributionNoContent {
	return &CartRemoveContributionNoContent{}
}

/*
CartRemoveContributionNoContent describes a response with status code 204, with default header values.

No Content
*/
type CartRemoveContributionNoContent struct {
}

// IsSuccess returns true when this cart remove contribution no content response has a 2xx status code
func (o *CartRemoveContributionNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this cart remove contribution no content response has a 3xx status code
func (o *CartRemoveContributionNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cart remove contribution no content response has a 4xx status code
func (o *CartRemoveContributionNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this cart remove contribution no content response has a 5xx status code
func (o *CartRemoveContributionNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this cart remove contribution no content response a status code equal to that given
func (o *CartRemoveContributionNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the cart remove contribution no content response
func (o *CartRemoveContributionNoContent) Code() int {
	return 204
}

func (o *CartRemoveContributionNoContent) Error() string {
	return fmt.Sprintf("[DELETE /Web/Cart/{sessionKey}/Contributions/{lineItemId}][%d] cartRemoveContributionNoContent", 204)
}

func (o *CartRemoveContributionNoContent) String() string {
	return fmt.Sprintf("[DELETE /Web/Cart/{sessionKey}/Contributions/{lineItemId}][%d] cartRemoveContributionNoContent", 204)
}

func (o *CartRemoveContributionNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewCartRemoveContributionDefault creates a CartRemoveContributionDefault with default headers values
func NewCartRemoveContributionDefault(code int) *CartRemoveContributionDefault {
	return &CartRemoveContributionDefault{
		_statusCode: code,
	}
}

/*
CartRemoveContributionDefault describes a response with status code -1, with default header values.

Error
*/
type CartRemoveContributionDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this cart remove contribution default response has a 2xx status code
func (o *CartRemoveContributionDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this cart remove contribution default response has a 3xx status code
func (o *CartRemoveContributionDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this cart remove contribution default response has a 4xx status code
func (o *CartRemoveContributionDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this cart remove contribution default response has a 5xx status code
func (o *CartRemoveContributionDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this cart remove contribution default response a status code equal to that given
func (o *CartRemoveContributionDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the cart remove contribution default response
func (o *CartRemoveContributionDefault) Code() int {
	return o._statusCode
}

func (o *CartRemoveContributionDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /Web/Cart/{sessionKey}/Contributions/{lineItemId}][%d] Cart_RemoveContribution default %s", o._statusCode, payload)
}

func (o *CartRemoveContributionDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /Web/Cart/{sessionKey}/Contributions/{lineItemId}][%d] Cart_RemoveContribution default %s", o._statusCode, payload)
}

func (o *CartRemoveContributionDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CartRemoveContributionDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}