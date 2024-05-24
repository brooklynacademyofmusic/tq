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

// DonationLevelsGetReader is a Reader for the DonationLevelsGet structure.
type DonationLevelsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DonationLevelsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDonationLevelsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewDonationLevelsGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewDonationLevelsGetOK creates a DonationLevelsGetOK with default headers values
func NewDonationLevelsGetOK() *DonationLevelsGetOK {
	return &DonationLevelsGetOK{}
}

/*
DonationLevelsGetOK describes a response with status code 200, with default header values.

OK
*/
type DonationLevelsGetOK struct {
	Payload *models.DonationLevel
}

// IsSuccess returns true when this donation levels get o k response has a 2xx status code
func (o *DonationLevelsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this donation levels get o k response has a 3xx status code
func (o *DonationLevelsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this donation levels get o k response has a 4xx status code
func (o *DonationLevelsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this donation levels get o k response has a 5xx status code
func (o *DonationLevelsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this donation levels get o k response a status code equal to that given
func (o *DonationLevelsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the donation levels get o k response
func (o *DonationLevelsGetOK) Code() int {
	return 200
}

func (o *DonationLevelsGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/DonationLevels/{id}][%d] donationLevelsGetOK %s", 200, payload)
}

func (o *DonationLevelsGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/DonationLevels/{id}][%d] donationLevelsGetOK %s", 200, payload)
}

func (o *DonationLevelsGetOK) GetPayload() *models.DonationLevel {
	return o.Payload
}

func (o *DonationLevelsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.DonationLevel)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDonationLevelsGetDefault creates a DonationLevelsGetDefault with default headers values
func NewDonationLevelsGetDefault(code int) *DonationLevelsGetDefault {
	return &DonationLevelsGetDefault{
		_statusCode: code,
	}
}

/*
DonationLevelsGetDefault describes a response with status code -1, with default header values.

Error
*/
type DonationLevelsGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this donation levels get default response has a 2xx status code
func (o *DonationLevelsGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this donation levels get default response has a 3xx status code
func (o *DonationLevelsGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this donation levels get default response has a 4xx status code
func (o *DonationLevelsGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this donation levels get default response has a 5xx status code
func (o *DonationLevelsGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this donation levels get default response a status code equal to that given
func (o *DonationLevelsGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the donation levels get default response
func (o *DonationLevelsGetDefault) Code() int {
	return o._statusCode
}

func (o *DonationLevelsGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/DonationLevels/{id}][%d] DonationLevels_Get default %s", o._statusCode, payload)
}

func (o *DonationLevelsGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/DonationLevels/{id}][%d] DonationLevels_Get default %s", o._statusCode, payload)
}

func (o *DonationLevelsGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *DonationLevelsGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
