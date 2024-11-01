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

// SourceGroupsDeleteReader is a Reader for the SourceGroupsDelete structure.
type SourceGroupsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SourceGroupsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewSourceGroupsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSourceGroupsDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSourceGroupsDeleteNoContent creates a SourceGroupsDeleteNoContent with default headers values
func NewSourceGroupsDeleteNoContent() *SourceGroupsDeleteNoContent {
	return &SourceGroupsDeleteNoContent{}
}

/*
SourceGroupsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type SourceGroupsDeleteNoContent struct {
}

// IsSuccess returns true when this source groups delete no content response has a 2xx status code
func (o *SourceGroupsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this source groups delete no content response has a 3xx status code
func (o *SourceGroupsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this source groups delete no content response has a 4xx status code
func (o *SourceGroupsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this source groups delete no content response has a 5xx status code
func (o *SourceGroupsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this source groups delete no content response a status code equal to that given
func (o *SourceGroupsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the source groups delete no content response
func (o *SourceGroupsDeleteNoContent) Code() int {
	return 204
}

func (o *SourceGroupsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/SourceGroups/{id}][%d] sourceGroupsDeleteNoContent", 204)
}

func (o *SourceGroupsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/SourceGroups/{id}][%d] sourceGroupsDeleteNoContent", 204)
}

func (o *SourceGroupsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewSourceGroupsDeleteDefault creates a SourceGroupsDeleteDefault with default headers values
func NewSourceGroupsDeleteDefault(code int) *SourceGroupsDeleteDefault {
	return &SourceGroupsDeleteDefault{
		_statusCode: code,
	}
}

/*
SourceGroupsDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type SourceGroupsDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this source groups delete default response has a 2xx status code
func (o *SourceGroupsDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this source groups delete default response has a 3xx status code
func (o *SourceGroupsDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this source groups delete default response has a 4xx status code
func (o *SourceGroupsDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this source groups delete default response has a 5xx status code
func (o *SourceGroupsDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this source groups delete default response a status code equal to that given
func (o *SourceGroupsDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the source groups delete default response
func (o *SourceGroupsDeleteDefault) Code() int {
	return o._statusCode
}

func (o *SourceGroupsDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/SourceGroups/{id}][%d] SourceGroups_Delete default %s", o._statusCode, payload)
}

func (o *SourceGroupsDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/SourceGroups/{id}][%d] SourceGroups_Delete default %s", o._statusCode, payload)
}

func (o *SourceGroupsDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SourceGroupsDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}