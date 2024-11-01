// Code generated by go-swagger; DO NOT EDIT.

package p_u_t

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

// SeatStatusesUpdateReader is a Reader for the SeatStatusesUpdate structure.
type SeatStatusesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SeatStatusesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSeatStatusesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSeatStatusesUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSeatStatusesUpdateOK creates a SeatStatusesUpdateOK with default headers values
func NewSeatStatusesUpdateOK() *SeatStatusesUpdateOK {
	return &SeatStatusesUpdateOK{}
}

/*
SeatStatusesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type SeatStatusesUpdateOK struct {
	Payload *models.SeatStatus
}

// IsSuccess returns true when this seat statuses update o k response has a 2xx status code
func (o *SeatStatusesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this seat statuses update o k response has a 3xx status code
func (o *SeatStatusesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this seat statuses update o k response has a 4xx status code
func (o *SeatStatusesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this seat statuses update o k response has a 5xx status code
func (o *SeatStatusesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this seat statuses update o k response a status code equal to that given
func (o *SeatStatusesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the seat statuses update o k response
func (o *SeatStatusesUpdateOK) Code() int {
	return 200
}

func (o *SeatStatusesUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/SeatStatuses/{id}][%d] seatStatusesUpdateOK %s", 200, payload)
}

func (o *SeatStatusesUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/SeatStatuses/{id}][%d] seatStatusesUpdateOK %s", 200, payload)
}

func (o *SeatStatusesUpdateOK) GetPayload() *models.SeatStatus {
	return o.Payload
}

func (o *SeatStatusesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SeatStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSeatStatusesUpdateDefault creates a SeatStatusesUpdateDefault with default headers values
func NewSeatStatusesUpdateDefault(code int) *SeatStatusesUpdateDefault {
	return &SeatStatusesUpdateDefault{
		_statusCode: code,
	}
}

/*
SeatStatusesUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type SeatStatusesUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this seat statuses update default response has a 2xx status code
func (o *SeatStatusesUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this seat statuses update default response has a 3xx status code
func (o *SeatStatusesUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this seat statuses update default response has a 4xx status code
func (o *SeatStatusesUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this seat statuses update default response has a 5xx status code
func (o *SeatStatusesUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this seat statuses update default response a status code equal to that given
func (o *SeatStatusesUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the seat statuses update default response
func (o *SeatStatusesUpdateDefault) Code() int {
	return o._statusCode
}

func (o *SeatStatusesUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/SeatStatuses/{id}][%d] SeatStatuses_Update default %s", o._statusCode, payload)
}

func (o *SeatStatusesUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/SeatStatuses/{id}][%d] SeatStatuses_Update default %s", o._statusCode, payload)
}

func (o *SeatStatusesUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SeatStatusesUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}