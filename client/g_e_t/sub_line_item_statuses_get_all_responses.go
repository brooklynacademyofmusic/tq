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

// SubLineItemStatusesGetAllReader is a Reader for the SubLineItemStatusesGetAll structure.
type SubLineItemStatusesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SubLineItemStatusesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSubLineItemStatusesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSubLineItemStatusesGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSubLineItemStatusesGetAllOK creates a SubLineItemStatusesGetAllOK with default headers values
func NewSubLineItemStatusesGetAllOK() *SubLineItemStatusesGetAllOK {
	return &SubLineItemStatusesGetAllOK{}
}

/*
SubLineItemStatusesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type SubLineItemStatusesGetAllOK struct {
	Payload []*models.SubLineItemStatus
}

// IsSuccess returns true when this sub line item statuses get all o k response has a 2xx status code
func (o *SubLineItemStatusesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this sub line item statuses get all o k response has a 3xx status code
func (o *SubLineItemStatusesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this sub line item statuses get all o k response has a 4xx status code
func (o *SubLineItemStatusesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this sub line item statuses get all o k response has a 5xx status code
func (o *SubLineItemStatusesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this sub line item statuses get all o k response a status code equal to that given
func (o *SubLineItemStatusesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the sub line item statuses get all o k response
func (o *SubLineItemStatusesGetAllOK) Code() int {
	return 200
}

func (o *SubLineItemStatusesGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SubLineItemStatuses][%d] subLineItemStatusesGetAllOK %s", 200, payload)
}

func (o *SubLineItemStatusesGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SubLineItemStatuses][%d] subLineItemStatusesGetAllOK %s", 200, payload)
}

func (o *SubLineItemStatusesGetAllOK) GetPayload() []*models.SubLineItemStatus {
	return o.Payload
}

func (o *SubLineItemStatusesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSubLineItemStatusesGetAllDefault creates a SubLineItemStatusesGetAllDefault with default headers values
func NewSubLineItemStatusesGetAllDefault(code int) *SubLineItemStatusesGetAllDefault {
	return &SubLineItemStatusesGetAllDefault{
		_statusCode: code,
	}
}

/*
SubLineItemStatusesGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type SubLineItemStatusesGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this sub line item statuses get all default response has a 2xx status code
func (o *SubLineItemStatusesGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this sub line item statuses get all default response has a 3xx status code
func (o *SubLineItemStatusesGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this sub line item statuses get all default response has a 4xx status code
func (o *SubLineItemStatusesGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this sub line item statuses get all default response has a 5xx status code
func (o *SubLineItemStatusesGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this sub line item statuses get all default response a status code equal to that given
func (o *SubLineItemStatusesGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the sub line item statuses get all default response
func (o *SubLineItemStatusesGetAllDefault) Code() int {
	return o._statusCode
}

func (o *SubLineItemStatusesGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SubLineItemStatuses][%d] SubLineItemStatuses_GetAll default %s", o._statusCode, payload)
}

func (o *SubLineItemStatusesGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SubLineItemStatuses][%d] SubLineItemStatuses_GetAll default %s", o._statusCode, payload)
}

func (o *SubLineItemStatusesGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SubLineItemStatusesGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}