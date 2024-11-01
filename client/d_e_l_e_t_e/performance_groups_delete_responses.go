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

// PerformanceGroupsDeleteReader is a Reader for the PerformanceGroupsDelete structure.
type PerformanceGroupsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PerformanceGroupsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewPerformanceGroupsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPerformanceGroupsDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPerformanceGroupsDeleteNoContent creates a PerformanceGroupsDeleteNoContent with default headers values
func NewPerformanceGroupsDeleteNoContent() *PerformanceGroupsDeleteNoContent {
	return &PerformanceGroupsDeleteNoContent{}
}

/*
PerformanceGroupsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type PerformanceGroupsDeleteNoContent struct {
}

// IsSuccess returns true when this performance groups delete no content response has a 2xx status code
func (o *PerformanceGroupsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this performance groups delete no content response has a 3xx status code
func (o *PerformanceGroupsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this performance groups delete no content response has a 4xx status code
func (o *PerformanceGroupsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this performance groups delete no content response has a 5xx status code
func (o *PerformanceGroupsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this performance groups delete no content response a status code equal to that given
func (o *PerformanceGroupsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the performance groups delete no content response
func (o *PerformanceGroupsDeleteNoContent) Code() int {
	return 204
}

func (o *PerformanceGroupsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /TXN/PerformanceGroups/{id}][%d] performanceGroupsDeleteNoContent", 204)
}

func (o *PerformanceGroupsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /TXN/PerformanceGroups/{id}][%d] performanceGroupsDeleteNoContent", 204)
}

func (o *PerformanceGroupsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPerformanceGroupsDeleteDefault creates a PerformanceGroupsDeleteDefault with default headers values
func NewPerformanceGroupsDeleteDefault(code int) *PerformanceGroupsDeleteDefault {
	return &PerformanceGroupsDeleteDefault{
		_statusCode: code,
	}
}

/*
PerformanceGroupsDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type PerformanceGroupsDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this performance groups delete default response has a 2xx status code
func (o *PerformanceGroupsDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this performance groups delete default response has a 3xx status code
func (o *PerformanceGroupsDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this performance groups delete default response has a 4xx status code
func (o *PerformanceGroupsDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this performance groups delete default response has a 5xx status code
func (o *PerformanceGroupsDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this performance groups delete default response a status code equal to that given
func (o *PerformanceGroupsDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the performance groups delete default response
func (o *PerformanceGroupsDeleteDefault) Code() int {
	return o._statusCode
}

func (o *PerformanceGroupsDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/PerformanceGroups/{id}][%d] PerformanceGroups_Delete default %s", o._statusCode, payload)
}

func (o *PerformanceGroupsDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/PerformanceGroups/{id}][%d] PerformanceGroups_Delete default %s", o._statusCode, payload)
}

func (o *PerformanceGroupsDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PerformanceGroupsDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}