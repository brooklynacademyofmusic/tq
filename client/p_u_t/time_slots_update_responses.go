// Code generated by go-swagger; DO NOT EDIT.

package p_u_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// TimeSlotsUpdateReader is a Reader for the TimeSlotsUpdate structure.
type TimeSlotsUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TimeSlotsUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewTimeSlotsUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[PUT /ReferenceData/TimeSlots/{id}] TimeSlots_Update", response, response.Code())
	}
}

// NewTimeSlotsUpdateOK creates a TimeSlotsUpdateOK with default headers values
func NewTimeSlotsUpdateOK() *TimeSlotsUpdateOK {
	return &TimeSlotsUpdateOK{}
}

/*
TimeSlotsUpdateOK describes a response with status code 200, with default header values.

OK
*/
type TimeSlotsUpdateOK struct {
	Payload *models.TimeSlot
}

// IsSuccess returns true when this time slots update o k response has a 2xx status code
func (o *TimeSlotsUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this time slots update o k response has a 3xx status code
func (o *TimeSlotsUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this time slots update o k response has a 4xx status code
func (o *TimeSlotsUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this time slots update o k response has a 5xx status code
func (o *TimeSlotsUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this time slots update o k response a status code equal to that given
func (o *TimeSlotsUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the time slots update o k response
func (o *TimeSlotsUpdateOK) Code() int {
	return 200
}

func (o *TimeSlotsUpdateOK) Error() string {
	return fmt.Sprintf("[PUT /ReferenceData/TimeSlots/{id}][%d] timeSlotsUpdateOK  %+v", 200, o.Payload)
}

func (o *TimeSlotsUpdateOK) String() string {
	return fmt.Sprintf("[PUT /ReferenceData/TimeSlots/{id}][%d] timeSlotsUpdateOK  %+v", 200, o.Payload)
}

func (o *TimeSlotsUpdateOK) GetPayload() *models.TimeSlot {
	return o.Payload
}

func (o *TimeSlotsUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.TimeSlot)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}