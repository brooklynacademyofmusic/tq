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

// BookingsDeleteDocumentReader is a Reader for the BookingsDeleteDocument structure.
type BookingsDeleteDocumentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *BookingsDeleteDocumentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewBookingsDeleteDocumentNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewBookingsDeleteDocumentDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewBookingsDeleteDocumentNoContent creates a BookingsDeleteDocumentNoContent with default headers values
func NewBookingsDeleteDocumentNoContent() *BookingsDeleteDocumentNoContent {
	return &BookingsDeleteDocumentNoContent{}
}

/*
BookingsDeleteDocumentNoContent describes a response with status code 204, with default header values.

No Content
*/
type BookingsDeleteDocumentNoContent struct {
}

// IsSuccess returns true when this bookings delete document no content response has a 2xx status code
func (o *BookingsDeleteDocumentNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this bookings delete document no content response has a 3xx status code
func (o *BookingsDeleteDocumentNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this bookings delete document no content response has a 4xx status code
func (o *BookingsDeleteDocumentNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this bookings delete document no content response has a 5xx status code
func (o *BookingsDeleteDocumentNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this bookings delete document no content response a status code equal to that given
func (o *BookingsDeleteDocumentNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the bookings delete document no content response
func (o *BookingsDeleteDocumentNoContent) Code() int {
	return 204
}

func (o *BookingsDeleteDocumentNoContent) Error() string {
	return fmt.Sprintf("[DELETE /EventsManagement/Bookings/{bookingId}/Documents/{documentId}][%d] bookingsDeleteDocumentNoContent", 204)
}

func (o *BookingsDeleteDocumentNoContent) String() string {
	return fmt.Sprintf("[DELETE /EventsManagement/Bookings/{bookingId}/Documents/{documentId}][%d] bookingsDeleteDocumentNoContent", 204)
}

func (o *BookingsDeleteDocumentNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewBookingsDeleteDocumentDefault creates a BookingsDeleteDocumentDefault with default headers values
func NewBookingsDeleteDocumentDefault(code int) *BookingsDeleteDocumentDefault {
	return &BookingsDeleteDocumentDefault{
		_statusCode: code,
	}
}

/*
BookingsDeleteDocumentDefault describes a response with status code -1, with default header values.

Error
*/
type BookingsDeleteDocumentDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this bookings delete document default response has a 2xx status code
func (o *BookingsDeleteDocumentDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this bookings delete document default response has a 3xx status code
func (o *BookingsDeleteDocumentDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this bookings delete document default response has a 4xx status code
func (o *BookingsDeleteDocumentDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this bookings delete document default response has a 5xx status code
func (o *BookingsDeleteDocumentDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this bookings delete document default response a status code equal to that given
func (o *BookingsDeleteDocumentDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the bookings delete document default response
func (o *BookingsDeleteDocumentDefault) Code() int {
	return o._statusCode
}

func (o *BookingsDeleteDocumentDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /EventsManagement/Bookings/{bookingId}/Documents/{documentId}][%d] Bookings_DeleteDocument default %s", o._statusCode, payload)
}

func (o *BookingsDeleteDocumentDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /EventsManagement/Bookings/{bookingId}/Documents/{documentId}][%d] Bookings_DeleteDocument default %s", o._statusCode, payload)
}

func (o *BookingsDeleteDocumentDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *BookingsDeleteDocumentDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
