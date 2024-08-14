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

// SeatCodesDeleteReader is a Reader for the SeatCodesDelete structure.
type SeatCodesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SeatCodesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewSeatCodesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSeatCodesDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSeatCodesDeleteNoContent creates a SeatCodesDeleteNoContent with default headers values
func NewSeatCodesDeleteNoContent() *SeatCodesDeleteNoContent {
	return &SeatCodesDeleteNoContent{}
}

/*
SeatCodesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type SeatCodesDeleteNoContent struct {
}

// IsSuccess returns true when this seat codes delete no content response has a 2xx status code
func (o *SeatCodesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this seat codes delete no content response has a 3xx status code
func (o *SeatCodesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this seat codes delete no content response has a 4xx status code
func (o *SeatCodesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this seat codes delete no content response has a 5xx status code
func (o *SeatCodesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this seat codes delete no content response a status code equal to that given
func (o *SeatCodesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the seat codes delete no content response
func (o *SeatCodesDeleteNoContent) Code() int {
	return 204
}

func (o *SeatCodesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/SeatCodes/{id}][%d] seatCodesDeleteNoContent", 204)
}

func (o *SeatCodesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/SeatCodes/{id}][%d] seatCodesDeleteNoContent", 204)
}

func (o *SeatCodesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewSeatCodesDeleteDefault creates a SeatCodesDeleteDefault with default headers values
func NewSeatCodesDeleteDefault(code int) *SeatCodesDeleteDefault {
	return &SeatCodesDeleteDefault{
		_statusCode: code,
	}
}

/*
SeatCodesDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type SeatCodesDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this seat codes delete default response has a 2xx status code
func (o *SeatCodesDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this seat codes delete default response has a 3xx status code
func (o *SeatCodesDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this seat codes delete default response has a 4xx status code
func (o *SeatCodesDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this seat codes delete default response has a 5xx status code
func (o *SeatCodesDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this seat codes delete default response a status code equal to that given
func (o *SeatCodesDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the seat codes delete default response
func (o *SeatCodesDeleteDefault) Code() int {
	return o._statusCode
}

func (o *SeatCodesDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/SeatCodes/{id}][%d] SeatCodes_Delete default %s", o._statusCode, payload)
}

func (o *SeatCodesDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/SeatCodes/{id}][%d] SeatCodes_Delete default %s", o._statusCode, payload)
}

func (o *SeatCodesDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SeatCodesDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}