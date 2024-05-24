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

// TimeSlotsGetAllReader is a Reader for the TimeSlotsGetAll structure.
type TimeSlotsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TimeSlotsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewTimeSlotsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewTimeSlotsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewTimeSlotsGetAllOK creates a TimeSlotsGetAllOK with default headers values
func NewTimeSlotsGetAllOK() *TimeSlotsGetAllOK {
	return &TimeSlotsGetAllOK{}
}

/*
TimeSlotsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type TimeSlotsGetAllOK struct {
	Payload []*models.TimeSlot
}

// IsSuccess returns true when this time slots get all o k response has a 2xx status code
func (o *TimeSlotsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this time slots get all o k response has a 3xx status code
func (o *TimeSlotsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this time slots get all o k response has a 4xx status code
func (o *TimeSlotsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this time slots get all o k response has a 5xx status code
func (o *TimeSlotsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this time slots get all o k response a status code equal to that given
func (o *TimeSlotsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the time slots get all o k response
func (o *TimeSlotsGetAllOK) Code() int {
	return 200
}

func (o *TimeSlotsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/TimeSlots][%d] timeSlotsGetAllOK %s", 200, payload)
}

func (o *TimeSlotsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/TimeSlots][%d] timeSlotsGetAllOK %s", 200, payload)
}

func (o *TimeSlotsGetAllOK) GetPayload() []*models.TimeSlot {
	return o.Payload
}

func (o *TimeSlotsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTimeSlotsGetAllDefault creates a TimeSlotsGetAllDefault with default headers values
func NewTimeSlotsGetAllDefault(code int) *TimeSlotsGetAllDefault {
	return &TimeSlotsGetAllDefault{
		_statusCode: code,
	}
}

/*
TimeSlotsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type TimeSlotsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this time slots get all default response has a 2xx status code
func (o *TimeSlotsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this time slots get all default response has a 3xx status code
func (o *TimeSlotsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this time slots get all default response has a 4xx status code
func (o *TimeSlotsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this time slots get all default response has a 5xx status code
func (o *TimeSlotsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this time slots get all default response a status code equal to that given
func (o *TimeSlotsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the time slots get all default response
func (o *TimeSlotsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *TimeSlotsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/TimeSlots][%d] TimeSlots_GetAll default %s", o._statusCode, payload)
}

func (o *TimeSlotsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/TimeSlots][%d] TimeSlots_GetAll default %s", o._statusCode, payload)
}

func (o *TimeSlotsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *TimeSlotsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
