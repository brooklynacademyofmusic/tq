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

// BookingCategoriesGetAllReader is a Reader for the BookingCategoriesGetAll structure.
type BookingCategoriesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *BookingCategoriesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewBookingCategoriesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewBookingCategoriesGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewBookingCategoriesGetAllOK creates a BookingCategoriesGetAllOK with default headers values
func NewBookingCategoriesGetAllOK() *BookingCategoriesGetAllOK {
	return &BookingCategoriesGetAllOK{}
}

/*
BookingCategoriesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type BookingCategoriesGetAllOK struct {
	Payload []*models.BookingCategory
}

// IsSuccess returns true when this booking categories get all o k response has a 2xx status code
func (o *BookingCategoriesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this booking categories get all o k response has a 3xx status code
func (o *BookingCategoriesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this booking categories get all o k response has a 4xx status code
func (o *BookingCategoriesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this booking categories get all o k response has a 5xx status code
func (o *BookingCategoriesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this booking categories get all o k response a status code equal to that given
func (o *BookingCategoriesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the booking categories get all o k response
func (o *BookingCategoriesGetAllOK) Code() int {
	return 200
}

func (o *BookingCategoriesGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/BookingCategories][%d] bookingCategoriesGetAllOK %s", 200, payload)
}

func (o *BookingCategoriesGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/BookingCategories][%d] bookingCategoriesGetAllOK %s", 200, payload)
}

func (o *BookingCategoriesGetAllOK) GetPayload() []*models.BookingCategory {
	return o.Payload
}

func (o *BookingCategoriesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewBookingCategoriesGetAllDefault creates a BookingCategoriesGetAllDefault with default headers values
func NewBookingCategoriesGetAllDefault(code int) *BookingCategoriesGetAllDefault {
	return &BookingCategoriesGetAllDefault{
		_statusCode: code,
	}
}

/*
BookingCategoriesGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type BookingCategoriesGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this booking categories get all default response has a 2xx status code
func (o *BookingCategoriesGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this booking categories get all default response has a 3xx status code
func (o *BookingCategoriesGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this booking categories get all default response has a 4xx status code
func (o *BookingCategoriesGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this booking categories get all default response has a 5xx status code
func (o *BookingCategoriesGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this booking categories get all default response a status code equal to that given
func (o *BookingCategoriesGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the booking categories get all default response
func (o *BookingCategoriesGetAllDefault) Code() int {
	return o._statusCode
}

func (o *BookingCategoriesGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/BookingCategories][%d] BookingCategories_GetAll default %s", o._statusCode, payload)
}

func (o *BookingCategoriesGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/BookingCategories][%d] BookingCategories_GetAll default %s", o._statusCode, payload)
}

func (o *BookingCategoriesGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *BookingCategoriesGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}