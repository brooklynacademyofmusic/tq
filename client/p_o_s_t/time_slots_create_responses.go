// Code generated by go-swagger; DO NOT EDIT.

package p_o_s_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// TimeSlotsCreateReader is a Reader for the TimeSlotsCreate structure.
type TimeSlotsCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TimeSlotsCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewTimeSlotsCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /ReferenceData/TimeSlots] TimeSlots_Create", response, response.Code())
	}
}

// NewTimeSlotsCreateOK creates a TimeSlotsCreateOK with default headers values
func NewTimeSlotsCreateOK() *TimeSlotsCreateOK {
	return &TimeSlotsCreateOK{}
}

/*
TimeSlotsCreateOK describes a response with status code 200, with default header values.

OK
*/
type TimeSlotsCreateOK struct {
	Payload *models.TimeSlot
}

// IsSuccess returns true when this time slots create o k response has a 2xx status code
func (o *TimeSlotsCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this time slots create o k response has a 3xx status code
func (o *TimeSlotsCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this time slots create o k response has a 4xx status code
func (o *TimeSlotsCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this time slots create o k response has a 5xx status code
func (o *TimeSlotsCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this time slots create o k response a status code equal to that given
func (o *TimeSlotsCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the time slots create o k response
func (o *TimeSlotsCreateOK) Code() int {
	return 200
}

func (o *TimeSlotsCreateOK) Error() string {
	return fmt.Sprintf("[POST /ReferenceData/TimeSlots][%d] timeSlotsCreateOK  %+v", 200, o.Payload)
}

func (o *TimeSlotsCreateOK) String() string {
	return fmt.Sprintf("[POST /ReferenceData/TimeSlots][%d] timeSlotsCreateOK  %+v", 200, o.Payload)
}

func (o *TimeSlotsCreateOK) GetPayload() *models.TimeSlot {
	return o.Payload
}

func (o *TimeSlotsCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.TimeSlot)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}