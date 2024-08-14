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

// MembershipLevelsGetAllReader is a Reader for the MembershipLevelsGetAll structure.
type MembershipLevelsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *MembershipLevelsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewMembershipLevelsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewMembershipLevelsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewMembershipLevelsGetAllOK creates a MembershipLevelsGetAllOK with default headers values
func NewMembershipLevelsGetAllOK() *MembershipLevelsGetAllOK {
	return &MembershipLevelsGetAllOK{}
}

/*
MembershipLevelsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type MembershipLevelsGetAllOK struct {
	Payload []*models.MembershipLevel
}

// IsSuccess returns true when this membership levels get all o k response has a 2xx status code
func (o *MembershipLevelsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this membership levels get all o k response has a 3xx status code
func (o *MembershipLevelsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this membership levels get all o k response has a 4xx status code
func (o *MembershipLevelsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this membership levels get all o k response has a 5xx status code
func (o *MembershipLevelsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this membership levels get all o k response a status code equal to that given
func (o *MembershipLevelsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the membership levels get all o k response
func (o *MembershipLevelsGetAllOK) Code() int {
	return 200
}

func (o *MembershipLevelsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/MembershipLevels][%d] membershipLevelsGetAllOK %s", 200, payload)
}

func (o *MembershipLevelsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/MembershipLevels][%d] membershipLevelsGetAllOK %s", 200, payload)
}

func (o *MembershipLevelsGetAllOK) GetPayload() []*models.MembershipLevel {
	return o.Payload
}

func (o *MembershipLevelsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewMembershipLevelsGetAllDefault creates a MembershipLevelsGetAllDefault with default headers values
func NewMembershipLevelsGetAllDefault(code int) *MembershipLevelsGetAllDefault {
	return &MembershipLevelsGetAllDefault{
		_statusCode: code,
	}
}

/*
MembershipLevelsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type MembershipLevelsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this membership levels get all default response has a 2xx status code
func (o *MembershipLevelsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this membership levels get all default response has a 3xx status code
func (o *MembershipLevelsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this membership levels get all default response has a 4xx status code
func (o *MembershipLevelsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this membership levels get all default response has a 5xx status code
func (o *MembershipLevelsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this membership levels get all default response a status code equal to that given
func (o *MembershipLevelsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the membership levels get all default response
func (o *MembershipLevelsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *MembershipLevelsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/MembershipLevels][%d] MembershipLevels_GetAll default %s", o._statusCode, payload)
}

func (o *MembershipLevelsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/MembershipLevels][%d] MembershipLevels_GetAll default %s", o._statusCode, payload)
}

func (o *MembershipLevelsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *MembershipLevelsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}