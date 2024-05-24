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

// SalesChannelsGetReader is a Reader for the SalesChannelsGet structure.
type SalesChannelsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SalesChannelsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSalesChannelsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSalesChannelsGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSalesChannelsGetOK creates a SalesChannelsGetOK with default headers values
func NewSalesChannelsGetOK() *SalesChannelsGetOK {
	return &SalesChannelsGetOK{}
}

/*
SalesChannelsGetOK describes a response with status code 200, with default header values.

OK
*/
type SalesChannelsGetOK struct {
	Payload *models.SalesChannel
}

// IsSuccess returns true when this sales channels get o k response has a 2xx status code
func (o *SalesChannelsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this sales channels get o k response has a 3xx status code
func (o *SalesChannelsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this sales channels get o k response has a 4xx status code
func (o *SalesChannelsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this sales channels get o k response has a 5xx status code
func (o *SalesChannelsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this sales channels get o k response a status code equal to that given
func (o *SalesChannelsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the sales channels get o k response
func (o *SalesChannelsGetOK) Code() int {
	return 200
}

func (o *SalesChannelsGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SalesChannels/{id}][%d] salesChannelsGetOK %s", 200, payload)
}

func (o *SalesChannelsGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SalesChannels/{id}][%d] salesChannelsGetOK %s", 200, payload)
}

func (o *SalesChannelsGetOK) GetPayload() *models.SalesChannel {
	return o.Payload
}

func (o *SalesChannelsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SalesChannel)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSalesChannelsGetDefault creates a SalesChannelsGetDefault with default headers values
func NewSalesChannelsGetDefault(code int) *SalesChannelsGetDefault {
	return &SalesChannelsGetDefault{
		_statusCode: code,
	}
}

/*
SalesChannelsGetDefault describes a response with status code -1, with default header values.

Error
*/
type SalesChannelsGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this sales channels get default response has a 2xx status code
func (o *SalesChannelsGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this sales channels get default response has a 3xx status code
func (o *SalesChannelsGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this sales channels get default response has a 4xx status code
func (o *SalesChannelsGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this sales channels get default response has a 5xx status code
func (o *SalesChannelsGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this sales channels get default response a status code equal to that given
func (o *SalesChannelsGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the sales channels get default response
func (o *SalesChannelsGetDefault) Code() int {
	return o._statusCode
}

func (o *SalesChannelsGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SalesChannels/{id}][%d] SalesChannels_Get default %s", o._statusCode, payload)
}

func (o *SalesChannelsGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SalesChannels/{id}][%d] SalesChannels_Get default %s", o._statusCode, payload)
}

func (o *SalesChannelsGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SalesChannelsGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
