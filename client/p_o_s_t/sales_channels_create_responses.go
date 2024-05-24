// Code generated by go-swagger; DO NOT EDIT.

package p_o_s_t

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

// SalesChannelsCreateReader is a Reader for the SalesChannelsCreate structure.
type SalesChannelsCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SalesChannelsCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSalesChannelsCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSalesChannelsCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSalesChannelsCreateOK creates a SalesChannelsCreateOK with default headers values
func NewSalesChannelsCreateOK() *SalesChannelsCreateOK {
	return &SalesChannelsCreateOK{}
}

/*
SalesChannelsCreateOK describes a response with status code 200, with default header values.

OK
*/
type SalesChannelsCreateOK struct {
	Payload *models.SalesChannel
}

// IsSuccess returns true when this sales channels create o k response has a 2xx status code
func (o *SalesChannelsCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this sales channels create o k response has a 3xx status code
func (o *SalesChannelsCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this sales channels create o k response has a 4xx status code
func (o *SalesChannelsCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this sales channels create o k response has a 5xx status code
func (o *SalesChannelsCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this sales channels create o k response a status code equal to that given
func (o *SalesChannelsCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the sales channels create o k response
func (o *SalesChannelsCreateOK) Code() int {
	return 200
}

func (o *SalesChannelsCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/SalesChannels][%d] salesChannelsCreateOK %s", 200, payload)
}

func (o *SalesChannelsCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/SalesChannels][%d] salesChannelsCreateOK %s", 200, payload)
}

func (o *SalesChannelsCreateOK) GetPayload() *models.SalesChannel {
	return o.Payload
}

func (o *SalesChannelsCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SalesChannel)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSalesChannelsCreateDefault creates a SalesChannelsCreateDefault with default headers values
func NewSalesChannelsCreateDefault(code int) *SalesChannelsCreateDefault {
	return &SalesChannelsCreateDefault{
		_statusCode: code,
	}
}

/*
SalesChannelsCreateDefault describes a response with status code -1, with default header values.

Error
*/
type SalesChannelsCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this sales channels create default response has a 2xx status code
func (o *SalesChannelsCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this sales channels create default response has a 3xx status code
func (o *SalesChannelsCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this sales channels create default response has a 4xx status code
func (o *SalesChannelsCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this sales channels create default response has a 5xx status code
func (o *SalesChannelsCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this sales channels create default response a status code equal to that given
func (o *SalesChannelsCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the sales channels create default response
func (o *SalesChannelsCreateDefault) Code() int {
	return o._statusCode
}

func (o *SalesChannelsCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/SalesChannels][%d] SalesChannels_Create default %s", o._statusCode, payload)
}

func (o *SalesChannelsCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/SalesChannels][%d] SalesChannels_Create default %s", o._statusCode, payload)
}

func (o *SalesChannelsCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SalesChannelsCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
