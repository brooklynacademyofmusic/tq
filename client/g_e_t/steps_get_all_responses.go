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

// StepsGetAllReader is a Reader for the StepsGetAll structure.
type StepsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *StepsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewStepsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewStepsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewStepsGetAllOK creates a StepsGetAllOK with default headers values
func NewStepsGetAllOK() *StepsGetAllOK {
	return &StepsGetAllOK{}
}

/*
StepsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type StepsGetAllOK struct {
	Payload []*models.Step
}

// IsSuccess returns true when this steps get all o k response has a 2xx status code
func (o *StepsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this steps get all o k response has a 3xx status code
func (o *StepsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this steps get all o k response has a 4xx status code
func (o *StepsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this steps get all o k response has a 5xx status code
func (o *StepsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this steps get all o k response a status code equal to that given
func (o *StepsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the steps get all o k response
func (o *StepsGetAllOK) Code() int {
	return 200
}

func (o *StepsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/Steps][%d] stepsGetAllOK %s", 200, payload)
}

func (o *StepsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/Steps][%d] stepsGetAllOK %s", 200, payload)
}

func (o *StepsGetAllOK) GetPayload() []*models.Step {
	return o.Payload
}

func (o *StepsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewStepsGetAllDefault creates a StepsGetAllDefault with default headers values
func NewStepsGetAllDefault(code int) *StepsGetAllDefault {
	return &StepsGetAllDefault{
		_statusCode: code,
	}
}

/*
StepsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type StepsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this steps get all default response has a 2xx status code
func (o *StepsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this steps get all default response has a 3xx status code
func (o *StepsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this steps get all default response has a 4xx status code
func (o *StepsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this steps get all default response has a 5xx status code
func (o *StepsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this steps get all default response a status code equal to that given
func (o *StepsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the steps get all default response
func (o *StepsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *StepsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/Steps][%d] Steps_GetAll default %s", o._statusCode, payload)
}

func (o *StepsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/Steps][%d] Steps_GetAll default %s", o._statusCode, payload)
}

func (o *StepsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *StepsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
