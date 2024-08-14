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

// BookingsGetSummaryReader is a Reader for the BookingsGetSummary structure.
type BookingsGetSummaryReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *BookingsGetSummaryReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewBookingsGetSummaryOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewBookingsGetSummaryDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewBookingsGetSummaryOK creates a BookingsGetSummaryOK with default headers values
func NewBookingsGetSummaryOK() *BookingsGetSummaryOK {
	return &BookingsGetSummaryOK{}
}

/*
BookingsGetSummaryOK describes a response with status code 200, with default header values.

OK
*/
type BookingsGetSummaryOK struct {
	Payload *models.BookingSummary
}

// IsSuccess returns true when this bookings get summary o k response has a 2xx status code
func (o *BookingsGetSummaryOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this bookings get summary o k response has a 3xx status code
func (o *BookingsGetSummaryOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this bookings get summary o k response has a 4xx status code
func (o *BookingsGetSummaryOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this bookings get summary o k response has a 5xx status code
func (o *BookingsGetSummaryOK) IsServerError() bool {
	return false
}

// IsCode returns true when this bookings get summary o k response a status code equal to that given
func (o *BookingsGetSummaryOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the bookings get summary o k response
func (o *BookingsGetSummaryOK) Code() int {
	return 200
}

func (o *BookingsGetSummaryOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /EventsManagement/Bookings/Summary/{bookingId}][%d] bookingsGetSummaryOK %s", 200, payload)
}

func (o *BookingsGetSummaryOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /EventsManagement/Bookings/Summary/{bookingId}][%d] bookingsGetSummaryOK %s", 200, payload)
}

func (o *BookingsGetSummaryOK) GetPayload() *models.BookingSummary {
	return o.Payload
}

func (o *BookingsGetSummaryOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BookingSummary)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewBookingsGetSummaryDefault creates a BookingsGetSummaryDefault with default headers values
func NewBookingsGetSummaryDefault(code int) *BookingsGetSummaryDefault {
	return &BookingsGetSummaryDefault{
		_statusCode: code,
	}
}

/*
BookingsGetSummaryDefault describes a response with status code -1, with default header values.

Error
*/
type BookingsGetSummaryDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this bookings get summary default response has a 2xx status code
func (o *BookingsGetSummaryDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this bookings get summary default response has a 3xx status code
func (o *BookingsGetSummaryDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this bookings get summary default response has a 4xx status code
func (o *BookingsGetSummaryDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this bookings get summary default response has a 5xx status code
func (o *BookingsGetSummaryDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this bookings get summary default response a status code equal to that given
func (o *BookingsGetSummaryDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the bookings get summary default response
func (o *BookingsGetSummaryDefault) Code() int {
	return o._statusCode
}

func (o *BookingsGetSummaryDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /EventsManagement/Bookings/Summary/{bookingId}][%d] Bookings_GetSummary default %s", o._statusCode, payload)
}

func (o *BookingsGetSummaryDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /EventsManagement/Bookings/Summary/{bookingId}][%d] Bookings_GetSummary default %s", o._statusCode, payload)
}

func (o *BookingsGetSummaryDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *BookingsGetSummaryDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}