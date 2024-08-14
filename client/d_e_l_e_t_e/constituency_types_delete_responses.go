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

// ConstituencyTypesDeleteReader is a Reader for the ConstituencyTypesDelete structure.
type ConstituencyTypesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ConstituencyTypesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewConstituencyTypesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewConstituencyTypesDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewConstituencyTypesDeleteNoContent creates a ConstituencyTypesDeleteNoContent with default headers values
func NewConstituencyTypesDeleteNoContent() *ConstituencyTypesDeleteNoContent {
	return &ConstituencyTypesDeleteNoContent{}
}

/*
ConstituencyTypesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type ConstituencyTypesDeleteNoContent struct {
}

// IsSuccess returns true when this constituency types delete no content response has a 2xx status code
func (o *ConstituencyTypesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this constituency types delete no content response has a 3xx status code
func (o *ConstituencyTypesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this constituency types delete no content response has a 4xx status code
func (o *ConstituencyTypesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this constituency types delete no content response has a 5xx status code
func (o *ConstituencyTypesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this constituency types delete no content response a status code equal to that given
func (o *ConstituencyTypesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the constituency types delete no content response
func (o *ConstituencyTypesDeleteNoContent) Code() int {
	return 204
}

func (o *ConstituencyTypesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ConstituencyTypes/{id}][%d] constituencyTypesDeleteNoContent", 204)
}

func (o *ConstituencyTypesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ConstituencyTypes/{id}][%d] constituencyTypesDeleteNoContent", 204)
}

func (o *ConstituencyTypesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewConstituencyTypesDeleteDefault creates a ConstituencyTypesDeleteDefault with default headers values
func NewConstituencyTypesDeleteDefault(code int) *ConstituencyTypesDeleteDefault {
	return &ConstituencyTypesDeleteDefault{
		_statusCode: code,
	}
}

/*
ConstituencyTypesDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type ConstituencyTypesDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this constituency types delete default response has a 2xx status code
func (o *ConstituencyTypesDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this constituency types delete default response has a 3xx status code
func (o *ConstituencyTypesDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this constituency types delete default response has a 4xx status code
func (o *ConstituencyTypesDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this constituency types delete default response has a 5xx status code
func (o *ConstituencyTypesDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this constituency types delete default response a status code equal to that given
func (o *ConstituencyTypesDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the constituency types delete default response
func (o *ConstituencyTypesDeleteDefault) Code() int {
	return o._statusCode
}

func (o *ConstituencyTypesDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/ConstituencyTypes/{id}][%d] ConstituencyTypes_Delete default %s", o._statusCode, payload)
}

func (o *ConstituencyTypesDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/ConstituencyTypes/{id}][%d] ConstituencyTypes_Delete default %s", o._statusCode, payload)
}

func (o *ConstituencyTypesDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ConstituencyTypesDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}