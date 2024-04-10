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

// SeatCodesCreateReader is a Reader for the SeatCodesCreate structure.
type SeatCodesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SeatCodesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSeatCodesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /ReferenceData/SeatCodes] SeatCodes_Create", response, response.Code())
	}
}

// NewSeatCodesCreateOK creates a SeatCodesCreateOK with default headers values
func NewSeatCodesCreateOK() *SeatCodesCreateOK {
	return &SeatCodesCreateOK{}
}

/*
SeatCodesCreateOK describes a response with status code 200, with default header values.

OK
*/
type SeatCodesCreateOK struct {
	Payload *models.SeatCode
}

// IsSuccess returns true when this seat codes create o k response has a 2xx status code
func (o *SeatCodesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this seat codes create o k response has a 3xx status code
func (o *SeatCodesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this seat codes create o k response has a 4xx status code
func (o *SeatCodesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this seat codes create o k response has a 5xx status code
func (o *SeatCodesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this seat codes create o k response a status code equal to that given
func (o *SeatCodesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the seat codes create o k response
func (o *SeatCodesCreateOK) Code() int {
	return 200
}

func (o *SeatCodesCreateOK) Error() string {
	return fmt.Sprintf("[POST /ReferenceData/SeatCodes][%d] seatCodesCreateOK  %+v", 200, o.Payload)
}

func (o *SeatCodesCreateOK) String() string {
	return fmt.Sprintf("[POST /ReferenceData/SeatCodes][%d] seatCodesCreateOK  %+v", 200, o.Payload)
}

func (o *SeatCodesCreateOK) GetPayload() *models.SeatCode {
	return o.Payload
}

func (o *SeatCodesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SeatCode)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}