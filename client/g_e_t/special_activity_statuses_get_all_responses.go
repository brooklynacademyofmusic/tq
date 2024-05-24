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

// SpecialActivityStatusesGetAllReader is a Reader for the SpecialActivityStatusesGetAll structure.
type SpecialActivityStatusesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SpecialActivityStatusesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSpecialActivityStatusesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSpecialActivityStatusesGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSpecialActivityStatusesGetAllOK creates a SpecialActivityStatusesGetAllOK with default headers values
func NewSpecialActivityStatusesGetAllOK() *SpecialActivityStatusesGetAllOK {
	return &SpecialActivityStatusesGetAllOK{}
}

/*
SpecialActivityStatusesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type SpecialActivityStatusesGetAllOK struct {
	Payload []*models.SpecialActivityStatus
}

// IsSuccess returns true when this special activity statuses get all o k response has a 2xx status code
func (o *SpecialActivityStatusesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this special activity statuses get all o k response has a 3xx status code
func (o *SpecialActivityStatusesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this special activity statuses get all o k response has a 4xx status code
func (o *SpecialActivityStatusesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this special activity statuses get all o k response has a 5xx status code
func (o *SpecialActivityStatusesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this special activity statuses get all o k response a status code equal to that given
func (o *SpecialActivityStatusesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the special activity statuses get all o k response
func (o *SpecialActivityStatusesGetAllOK) Code() int {
	return 200
}

func (o *SpecialActivityStatusesGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SpecialActivityStatuses][%d] specialActivityStatusesGetAllOK %s", 200, payload)
}

func (o *SpecialActivityStatusesGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SpecialActivityStatuses][%d] specialActivityStatusesGetAllOK %s", 200, payload)
}

func (o *SpecialActivityStatusesGetAllOK) GetPayload() []*models.SpecialActivityStatus {
	return o.Payload
}

func (o *SpecialActivityStatusesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSpecialActivityStatusesGetAllDefault creates a SpecialActivityStatusesGetAllDefault with default headers values
func NewSpecialActivityStatusesGetAllDefault(code int) *SpecialActivityStatusesGetAllDefault {
	return &SpecialActivityStatusesGetAllDefault{
		_statusCode: code,
	}
}

/*
SpecialActivityStatusesGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type SpecialActivityStatusesGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this special activity statuses get all default response has a 2xx status code
func (o *SpecialActivityStatusesGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this special activity statuses get all default response has a 3xx status code
func (o *SpecialActivityStatusesGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this special activity statuses get all default response has a 4xx status code
func (o *SpecialActivityStatusesGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this special activity statuses get all default response has a 5xx status code
func (o *SpecialActivityStatusesGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this special activity statuses get all default response a status code equal to that given
func (o *SpecialActivityStatusesGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the special activity statuses get all default response
func (o *SpecialActivityStatusesGetAllDefault) Code() int {
	return o._statusCode
}

func (o *SpecialActivityStatusesGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SpecialActivityStatuses][%d] SpecialActivityStatuses_GetAll default %s", o._statusCode, payload)
}

func (o *SpecialActivityStatusesGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SpecialActivityStatuses][%d] SpecialActivityStatuses_GetAll default %s", o._statusCode, payload)
}

func (o *SpecialActivityStatusesGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SpecialActivityStatusesGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
