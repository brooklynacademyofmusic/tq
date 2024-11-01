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

// PerformancesGetSeatHoldDetailsReader is a Reader for the PerformancesGetSeatHoldDetails structure.
type PerformancesGetSeatHoldDetailsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PerformancesGetSeatHoldDetailsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPerformancesGetSeatHoldDetailsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPerformancesGetSeatHoldDetailsDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPerformancesGetSeatHoldDetailsOK creates a PerformancesGetSeatHoldDetailsOK with default headers values
func NewPerformancesGetSeatHoldDetailsOK() *PerformancesGetSeatHoldDetailsOK {
	return &PerformancesGetSeatHoldDetailsOK{}
}

/*
PerformancesGetSeatHoldDetailsOK describes a response with status code 200, with default header values.

OK
*/
type PerformancesGetSeatHoldDetailsOK struct {
	Payload []*models.SeatHoldDetail
}

// IsSuccess returns true when this performances get seat hold details o k response has a 2xx status code
func (o *PerformancesGetSeatHoldDetailsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this performances get seat hold details o k response has a 3xx status code
func (o *PerformancesGetSeatHoldDetailsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this performances get seat hold details o k response has a 4xx status code
func (o *PerformancesGetSeatHoldDetailsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this performances get seat hold details o k response has a 5xx status code
func (o *PerformancesGetSeatHoldDetailsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this performances get seat hold details o k response a status code equal to that given
func (o *PerformancesGetSeatHoldDetailsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the performances get seat hold details o k response
func (o *PerformancesGetSeatHoldDetailsOK) Code() int {
	return 200
}

func (o *PerformancesGetSeatHoldDetailsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Performances/{performanceId}/Seats/Holds][%d] performancesGetSeatHoldDetailsOK %s", 200, payload)
}

func (o *PerformancesGetSeatHoldDetailsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Performances/{performanceId}/Seats/Holds][%d] performancesGetSeatHoldDetailsOK %s", 200, payload)
}

func (o *PerformancesGetSeatHoldDetailsOK) GetPayload() []*models.SeatHoldDetail {
	return o.Payload
}

func (o *PerformancesGetSeatHoldDetailsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPerformancesGetSeatHoldDetailsDefault creates a PerformancesGetSeatHoldDetailsDefault with default headers values
func NewPerformancesGetSeatHoldDetailsDefault(code int) *PerformancesGetSeatHoldDetailsDefault {
	return &PerformancesGetSeatHoldDetailsDefault{
		_statusCode: code,
	}
}

/*
PerformancesGetSeatHoldDetailsDefault describes a response with status code -1, with default header values.

Error
*/
type PerformancesGetSeatHoldDetailsDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this performances get seat hold details default response has a 2xx status code
func (o *PerformancesGetSeatHoldDetailsDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this performances get seat hold details default response has a 3xx status code
func (o *PerformancesGetSeatHoldDetailsDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this performances get seat hold details default response has a 4xx status code
func (o *PerformancesGetSeatHoldDetailsDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this performances get seat hold details default response has a 5xx status code
func (o *PerformancesGetSeatHoldDetailsDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this performances get seat hold details default response a status code equal to that given
func (o *PerformancesGetSeatHoldDetailsDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the performances get seat hold details default response
func (o *PerformancesGetSeatHoldDetailsDefault) Code() int {
	return o._statusCode
}

func (o *PerformancesGetSeatHoldDetailsDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Performances/{performanceId}/Seats/Holds][%d] Performances_GetSeatHoldDetails default %s", o._statusCode, payload)
}

func (o *PerformancesGetSeatHoldDetailsDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Performances/{performanceId}/Seats/Holds][%d] Performances_GetSeatHoldDetails default %s", o._statusCode, payload)
}

func (o *PerformancesGetSeatHoldDetailsDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PerformancesGetSeatHoldDetailsDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}