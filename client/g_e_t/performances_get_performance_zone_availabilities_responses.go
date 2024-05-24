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

// PerformancesGetPerformanceZoneAvailabilitiesReader is a Reader for the PerformancesGetPerformanceZoneAvailabilities structure.
type PerformancesGetPerformanceZoneAvailabilitiesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PerformancesGetPerformanceZoneAvailabilitiesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPerformancesGetPerformanceZoneAvailabilitiesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPerformancesGetPerformanceZoneAvailabilitiesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPerformancesGetPerformanceZoneAvailabilitiesOK creates a PerformancesGetPerformanceZoneAvailabilitiesOK with default headers values
func NewPerformancesGetPerformanceZoneAvailabilitiesOK() *PerformancesGetPerformanceZoneAvailabilitiesOK {
	return &PerformancesGetPerformanceZoneAvailabilitiesOK{}
}

/*
PerformancesGetPerformanceZoneAvailabilitiesOK describes a response with status code 200, with default header values.

OK
*/
type PerformancesGetPerformanceZoneAvailabilitiesOK struct {
	Payload []*models.PerformanceZoneAvailability
}

// IsSuccess returns true when this performances get performance zone availabilities o k response has a 2xx status code
func (o *PerformancesGetPerformanceZoneAvailabilitiesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this performances get performance zone availabilities o k response has a 3xx status code
func (o *PerformancesGetPerformanceZoneAvailabilitiesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this performances get performance zone availabilities o k response has a 4xx status code
func (o *PerformancesGetPerformanceZoneAvailabilitiesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this performances get performance zone availabilities o k response has a 5xx status code
func (o *PerformancesGetPerformanceZoneAvailabilitiesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this performances get performance zone availabilities o k response a status code equal to that given
func (o *PerformancesGetPerformanceZoneAvailabilitiesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the performances get performance zone availabilities o k response
func (o *PerformancesGetPerformanceZoneAvailabilitiesOK) Code() int {
	return 200
}

func (o *PerformancesGetPerformanceZoneAvailabilitiesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Performances/Zones][%d] performancesGetPerformanceZoneAvailabilitiesOK %s", 200, payload)
}

func (o *PerformancesGetPerformanceZoneAvailabilitiesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Performances/Zones][%d] performancesGetPerformanceZoneAvailabilitiesOK %s", 200, payload)
}

func (o *PerformancesGetPerformanceZoneAvailabilitiesOK) GetPayload() []*models.PerformanceZoneAvailability {
	return o.Payload
}

func (o *PerformancesGetPerformanceZoneAvailabilitiesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPerformancesGetPerformanceZoneAvailabilitiesDefault creates a PerformancesGetPerformanceZoneAvailabilitiesDefault with default headers values
func NewPerformancesGetPerformanceZoneAvailabilitiesDefault(code int) *PerformancesGetPerformanceZoneAvailabilitiesDefault {
	return &PerformancesGetPerformanceZoneAvailabilitiesDefault{
		_statusCode: code,
	}
}

/*
PerformancesGetPerformanceZoneAvailabilitiesDefault describes a response with status code -1, with default header values.

Error
*/
type PerformancesGetPerformanceZoneAvailabilitiesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this performances get performance zone availabilities default response has a 2xx status code
func (o *PerformancesGetPerformanceZoneAvailabilitiesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this performances get performance zone availabilities default response has a 3xx status code
func (o *PerformancesGetPerformanceZoneAvailabilitiesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this performances get performance zone availabilities default response has a 4xx status code
func (o *PerformancesGetPerformanceZoneAvailabilitiesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this performances get performance zone availabilities default response has a 5xx status code
func (o *PerformancesGetPerformanceZoneAvailabilitiesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this performances get performance zone availabilities default response a status code equal to that given
func (o *PerformancesGetPerformanceZoneAvailabilitiesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the performances get performance zone availabilities default response
func (o *PerformancesGetPerformanceZoneAvailabilitiesDefault) Code() int {
	return o._statusCode
}

func (o *PerformancesGetPerformanceZoneAvailabilitiesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Performances/Zones][%d] Performances_GetPerformanceZoneAvailabilities default %s", o._statusCode, payload)
}

func (o *PerformancesGetPerformanceZoneAvailabilitiesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Performances/Zones][%d] Performances_GetPerformanceZoneAvailabilities default %s", o._statusCode, payload)
}

func (o *PerformancesGetPerformanceZoneAvailabilitiesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PerformancesGetPerformanceZoneAvailabilitiesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
