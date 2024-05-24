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

// SalesChannelsGetSummariesReader is a Reader for the SalesChannelsGetSummaries structure.
type SalesChannelsGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SalesChannelsGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSalesChannelsGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSalesChannelsGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSalesChannelsGetSummariesOK creates a SalesChannelsGetSummariesOK with default headers values
func NewSalesChannelsGetSummariesOK() *SalesChannelsGetSummariesOK {
	return &SalesChannelsGetSummariesOK{}
}

/*
SalesChannelsGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type SalesChannelsGetSummariesOK struct {
	Payload []*models.SalesChannelSummary
}

// IsSuccess returns true when this sales channels get summaries o k response has a 2xx status code
func (o *SalesChannelsGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this sales channels get summaries o k response has a 3xx status code
func (o *SalesChannelsGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this sales channels get summaries o k response has a 4xx status code
func (o *SalesChannelsGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this sales channels get summaries o k response has a 5xx status code
func (o *SalesChannelsGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this sales channels get summaries o k response a status code equal to that given
func (o *SalesChannelsGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the sales channels get summaries o k response
func (o *SalesChannelsGetSummariesOK) Code() int {
	return 200
}

func (o *SalesChannelsGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SalesChannels/Summary][%d] salesChannelsGetSummariesOK %s", 200, payload)
}

func (o *SalesChannelsGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SalesChannels/Summary][%d] salesChannelsGetSummariesOK %s", 200, payload)
}

func (o *SalesChannelsGetSummariesOK) GetPayload() []*models.SalesChannelSummary {
	return o.Payload
}

func (o *SalesChannelsGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSalesChannelsGetSummariesDefault creates a SalesChannelsGetSummariesDefault with default headers values
func NewSalesChannelsGetSummariesDefault(code int) *SalesChannelsGetSummariesDefault {
	return &SalesChannelsGetSummariesDefault{
		_statusCode: code,
	}
}

/*
SalesChannelsGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type SalesChannelsGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this sales channels get summaries default response has a 2xx status code
func (o *SalesChannelsGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this sales channels get summaries default response has a 3xx status code
func (o *SalesChannelsGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this sales channels get summaries default response has a 4xx status code
func (o *SalesChannelsGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this sales channels get summaries default response has a 5xx status code
func (o *SalesChannelsGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this sales channels get summaries default response a status code equal to that given
func (o *SalesChannelsGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the sales channels get summaries default response
func (o *SalesChannelsGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *SalesChannelsGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SalesChannels/Summary][%d] SalesChannels_GetSummaries default %s", o._statusCode, payload)
}

func (o *SalesChannelsGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SalesChannels/Summary][%d] SalesChannels_GetSummaries default %s", o._statusCode, payload)
}

func (o *SalesChannelsGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SalesChannelsGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
