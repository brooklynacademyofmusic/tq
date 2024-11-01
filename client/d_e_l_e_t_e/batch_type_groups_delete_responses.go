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

// BatchTypeGroupsDeleteReader is a Reader for the BatchTypeGroupsDelete structure.
type BatchTypeGroupsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *BatchTypeGroupsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewBatchTypeGroupsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewBatchTypeGroupsDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewBatchTypeGroupsDeleteNoContent creates a BatchTypeGroupsDeleteNoContent with default headers values
func NewBatchTypeGroupsDeleteNoContent() *BatchTypeGroupsDeleteNoContent {
	return &BatchTypeGroupsDeleteNoContent{}
}

/*
BatchTypeGroupsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type BatchTypeGroupsDeleteNoContent struct {
}

// IsSuccess returns true when this batch type groups delete no content response has a 2xx status code
func (o *BatchTypeGroupsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this batch type groups delete no content response has a 3xx status code
func (o *BatchTypeGroupsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this batch type groups delete no content response has a 4xx status code
func (o *BatchTypeGroupsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this batch type groups delete no content response has a 5xx status code
func (o *BatchTypeGroupsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this batch type groups delete no content response a status code equal to that given
func (o *BatchTypeGroupsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the batch type groups delete no content response
func (o *BatchTypeGroupsDeleteNoContent) Code() int {
	return 204
}

func (o *BatchTypeGroupsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/BatchTypeGroups/{id}][%d] batchTypeGroupsDeleteNoContent", 204)
}

func (o *BatchTypeGroupsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/BatchTypeGroups/{id}][%d] batchTypeGroupsDeleteNoContent", 204)
}

func (o *BatchTypeGroupsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewBatchTypeGroupsDeleteDefault creates a BatchTypeGroupsDeleteDefault with default headers values
func NewBatchTypeGroupsDeleteDefault(code int) *BatchTypeGroupsDeleteDefault {
	return &BatchTypeGroupsDeleteDefault{
		_statusCode: code,
	}
}

/*
BatchTypeGroupsDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type BatchTypeGroupsDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this batch type groups delete default response has a 2xx status code
func (o *BatchTypeGroupsDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this batch type groups delete default response has a 3xx status code
func (o *BatchTypeGroupsDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this batch type groups delete default response has a 4xx status code
func (o *BatchTypeGroupsDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this batch type groups delete default response has a 5xx status code
func (o *BatchTypeGroupsDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this batch type groups delete default response a status code equal to that given
func (o *BatchTypeGroupsDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the batch type groups delete default response
func (o *BatchTypeGroupsDeleteDefault) Code() int {
	return o._statusCode
}

func (o *BatchTypeGroupsDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/BatchTypeGroups/{id}][%d] BatchTypeGroups_Delete default %s", o._statusCode, payload)
}

func (o *BatchTypeGroupsDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/BatchTypeGroups/{id}][%d] BatchTypeGroups_Delete default %s", o._statusCode, payload)
}

func (o *BatchTypeGroupsDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *BatchTypeGroupsDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}