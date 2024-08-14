// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

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

// ModeOfSaleUserGroupsDeleteReader is a Reader for the ModeOfSaleUserGroupsDelete structure.
type ModeOfSaleUserGroupsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ModeOfSaleUserGroupsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewModeOfSaleUserGroupsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewModeOfSaleUserGroupsDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewModeOfSaleUserGroupsDeleteNoContent creates a ModeOfSaleUserGroupsDeleteNoContent with default headers values
func NewModeOfSaleUserGroupsDeleteNoContent() *ModeOfSaleUserGroupsDeleteNoContent {
	return &ModeOfSaleUserGroupsDeleteNoContent{}
}

/*
ModeOfSaleUserGroupsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type ModeOfSaleUserGroupsDeleteNoContent struct {
}

// IsSuccess returns true when this mode of sale user groups delete no content response has a 2xx status code
func (o *ModeOfSaleUserGroupsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this mode of sale user groups delete no content response has a 3xx status code
func (o *ModeOfSaleUserGroupsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this mode of sale user groups delete no content response has a 4xx status code
func (o *ModeOfSaleUserGroupsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this mode of sale user groups delete no content response has a 5xx status code
func (o *ModeOfSaleUserGroupsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this mode of sale user groups delete no content response a status code equal to that given
func (o *ModeOfSaleUserGroupsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the mode of sale user groups delete no content response
func (o *ModeOfSaleUserGroupsDeleteNoContent) Code() int {
	return 204
}

func (o *ModeOfSaleUserGroupsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /TXN/ModeOfSaleUserGroups/{modeOfSaleUserGroupId}][%d] modeOfSaleUserGroupsDeleteNoContent", 204)
}

func (o *ModeOfSaleUserGroupsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /TXN/ModeOfSaleUserGroups/{modeOfSaleUserGroupId}][%d] modeOfSaleUserGroupsDeleteNoContent", 204)
}

func (o *ModeOfSaleUserGroupsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewModeOfSaleUserGroupsDeleteDefault creates a ModeOfSaleUserGroupsDeleteDefault with default headers values
func NewModeOfSaleUserGroupsDeleteDefault(code int) *ModeOfSaleUserGroupsDeleteDefault {
	return &ModeOfSaleUserGroupsDeleteDefault{
		_statusCode: code,
	}
}

/*
ModeOfSaleUserGroupsDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type ModeOfSaleUserGroupsDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this mode of sale user groups delete default response has a 2xx status code
func (o *ModeOfSaleUserGroupsDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this mode of sale user groups delete default response has a 3xx status code
func (o *ModeOfSaleUserGroupsDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this mode of sale user groups delete default response has a 4xx status code
func (o *ModeOfSaleUserGroupsDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this mode of sale user groups delete default response has a 5xx status code
func (o *ModeOfSaleUserGroupsDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this mode of sale user groups delete default response a status code equal to that given
func (o *ModeOfSaleUserGroupsDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the mode of sale user groups delete default response
func (o *ModeOfSaleUserGroupsDeleteDefault) Code() int {
	return o._statusCode
}

func (o *ModeOfSaleUserGroupsDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/ModeOfSaleUserGroups/{modeOfSaleUserGroupId}][%d] ModeOfSaleUserGroups_Delete default %s", o._statusCode, payload)
}

func (o *ModeOfSaleUserGroupsDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/ModeOfSaleUserGroups/{modeOfSaleUserGroupId}][%d] ModeOfSaleUserGroups_Delete default %s", o._statusCode, payload)
}

func (o *ModeOfSaleUserGroupsDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ModeOfSaleUserGroupsDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}