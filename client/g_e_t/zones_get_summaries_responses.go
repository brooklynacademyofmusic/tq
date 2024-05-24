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

// ZonesGetSummariesReader is a Reader for the ZonesGetSummaries structure.
type ZonesGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ZonesGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewZonesGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewZonesGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewZonesGetSummariesOK creates a ZonesGetSummariesOK with default headers values
func NewZonesGetSummariesOK() *ZonesGetSummariesOK {
	return &ZonesGetSummariesOK{}
}

/*
ZonesGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type ZonesGetSummariesOK struct {
	Payload []*models.ZoneSummary
}

// IsSuccess returns true when this zones get summaries o k response has a 2xx status code
func (o *ZonesGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this zones get summaries o k response has a 3xx status code
func (o *ZonesGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this zones get summaries o k response has a 4xx status code
func (o *ZonesGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this zones get summaries o k response has a 5xx status code
func (o *ZonesGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this zones get summaries o k response a status code equal to that given
func (o *ZonesGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the zones get summaries o k response
func (o *ZonesGetSummariesOK) Code() int {
	return 200
}

func (o *ZonesGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Zones/Summary][%d] zonesGetSummariesOK %s", 200, payload)
}

func (o *ZonesGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Zones/Summary][%d] zonesGetSummariesOK %s", 200, payload)
}

func (o *ZonesGetSummariesOK) GetPayload() []*models.ZoneSummary {
	return o.Payload
}

func (o *ZonesGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewZonesGetSummariesDefault creates a ZonesGetSummariesDefault with default headers values
func NewZonesGetSummariesDefault(code int) *ZonesGetSummariesDefault {
	return &ZonesGetSummariesDefault{
		_statusCode: code,
	}
}

/*
ZonesGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type ZonesGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this zones get summaries default response has a 2xx status code
func (o *ZonesGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this zones get summaries default response has a 3xx status code
func (o *ZonesGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this zones get summaries default response has a 4xx status code
func (o *ZonesGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this zones get summaries default response has a 5xx status code
func (o *ZonesGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this zones get summaries default response a status code equal to that given
func (o *ZonesGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the zones get summaries default response
func (o *ZonesGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *ZonesGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Zones/Summary][%d] Zones_GetSummaries default %s", o._statusCode, payload)
}

func (o *ZonesGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Zones/Summary][%d] Zones_GetSummaries default %s", o._statusCode, payload)
}

func (o *ZonesGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ZonesGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
