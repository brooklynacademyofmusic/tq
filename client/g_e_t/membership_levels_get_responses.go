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

// MembershipLevelsGetReader is a Reader for the MembershipLevelsGet structure.
type MembershipLevelsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *MembershipLevelsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewMembershipLevelsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewMembershipLevelsGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewMembershipLevelsGetOK creates a MembershipLevelsGetOK with default headers values
func NewMembershipLevelsGetOK() *MembershipLevelsGetOK {
	return &MembershipLevelsGetOK{}
}

/*
MembershipLevelsGetOK describes a response with status code 200, with default header values.

OK
*/
type MembershipLevelsGetOK struct {
	Payload *models.MembershipLevel
}

// IsSuccess returns true when this membership levels get o k response has a 2xx status code
func (o *MembershipLevelsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this membership levels get o k response has a 3xx status code
func (o *MembershipLevelsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this membership levels get o k response has a 4xx status code
func (o *MembershipLevelsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this membership levels get o k response has a 5xx status code
func (o *MembershipLevelsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this membership levels get o k response a status code equal to that given
func (o *MembershipLevelsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the membership levels get o k response
func (o *MembershipLevelsGetOK) Code() int {
	return 200
}

func (o *MembershipLevelsGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/MembershipLevels/{membershipLevelId}][%d] membershipLevelsGetOK %s", 200, payload)
}

func (o *MembershipLevelsGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/MembershipLevels/{membershipLevelId}][%d] membershipLevelsGetOK %s", 200, payload)
}

func (o *MembershipLevelsGetOK) GetPayload() *models.MembershipLevel {
	return o.Payload
}

func (o *MembershipLevelsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.MembershipLevel)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewMembershipLevelsGetDefault creates a MembershipLevelsGetDefault with default headers values
func NewMembershipLevelsGetDefault(code int) *MembershipLevelsGetDefault {
	return &MembershipLevelsGetDefault{
		_statusCode: code,
	}
}

/*
MembershipLevelsGetDefault describes a response with status code -1, with default header values.

Error
*/
type MembershipLevelsGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this membership levels get default response has a 2xx status code
func (o *MembershipLevelsGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this membership levels get default response has a 3xx status code
func (o *MembershipLevelsGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this membership levels get default response has a 4xx status code
func (o *MembershipLevelsGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this membership levels get default response has a 5xx status code
func (o *MembershipLevelsGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this membership levels get default response a status code equal to that given
func (o *MembershipLevelsGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the membership levels get default response
func (o *MembershipLevelsGetDefault) Code() int {
	return o._statusCode
}

func (o *MembershipLevelsGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/MembershipLevels/{membershipLevelId}][%d] MembershipLevels_Get default %s", o._statusCode, payload)
}

func (o *MembershipLevelsGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/MembershipLevels/{membershipLevelId}][%d] MembershipLevels_Get default %s", o._statusCode, payload)
}

func (o *MembershipLevelsGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *MembershipLevelsGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}