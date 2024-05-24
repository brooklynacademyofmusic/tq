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

// EMVSetIdleMessageReader is a Reader for the EMVSetIdleMessage structure.
type EMVSetIdleMessageReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *EMVSetIdleMessageReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewEMVSetIdleMessageOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewEMVSetIdleMessageDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewEMVSetIdleMessageOK creates a EMVSetIdleMessageOK with default headers values
func NewEMVSetIdleMessageOK() *EMVSetIdleMessageOK {
	return &EMVSetIdleMessageOK{}
}

/*
EMVSetIdleMessageOK describes a response with status code 200, with default header values.

OK
*/
type EMVSetIdleMessageOK struct {
	Payload *models.Profile
}

// IsSuccess returns true when this e m v set idle message o k response has a 2xx status code
func (o *EMVSetIdleMessageOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this e m v set idle message o k response has a 3xx status code
func (o *EMVSetIdleMessageOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this e m v set idle message o k response has a 4xx status code
func (o *EMVSetIdleMessageOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this e m v set idle message o k response has a 5xx status code
func (o *EMVSetIdleMessageOK) IsServerError() bool {
	return false
}

// IsCode returns true when this e m v set idle message o k response a status code equal to that given
func (o *EMVSetIdleMessageOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the e m v set idle message o k response
func (o *EMVSetIdleMessageOK) Code() int {
	return 200
}

func (o *EMVSetIdleMessageOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /PaymentGateway/EMV/TriPosLanes/{laneId}/Profiles/Idle][%d] eMVSetIdleMessageOK %s", 200, payload)
}

func (o *EMVSetIdleMessageOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /PaymentGateway/EMV/TriPosLanes/{laneId}/Profiles/Idle][%d] eMVSetIdleMessageOK %s", 200, payload)
}

func (o *EMVSetIdleMessageOK) GetPayload() *models.Profile {
	return o.Payload
}

func (o *EMVSetIdleMessageOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Profile)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewEMVSetIdleMessageDefault creates a EMVSetIdleMessageDefault with default headers values
func NewEMVSetIdleMessageDefault(code int) *EMVSetIdleMessageDefault {
	return &EMVSetIdleMessageDefault{
		_statusCode: code,
	}
}

/*
EMVSetIdleMessageDefault describes a response with status code -1, with default header values.

Error
*/
type EMVSetIdleMessageDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this e m v set idle message default response has a 2xx status code
func (o *EMVSetIdleMessageDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this e m v set idle message default response has a 3xx status code
func (o *EMVSetIdleMessageDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this e m v set idle message default response has a 4xx status code
func (o *EMVSetIdleMessageDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this e m v set idle message default response has a 5xx status code
func (o *EMVSetIdleMessageDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this e m v set idle message default response a status code equal to that given
func (o *EMVSetIdleMessageDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the e m v set idle message default response
func (o *EMVSetIdleMessageDefault) Code() int {
	return o._statusCode
}

func (o *EMVSetIdleMessageDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /PaymentGateway/EMV/TriPosLanes/{laneId}/Profiles/Idle][%d] EMV_SetIdleMessage default %s", o._statusCode, payload)
}

func (o *EMVSetIdleMessageDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /PaymentGateway/EMV/TriPosLanes/{laneId}/Profiles/Idle][%d] EMV_SetIdleMessage default %s", o._statusCode, payload)
}

func (o *EMVSetIdleMessageDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *EMVSetIdleMessageDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
