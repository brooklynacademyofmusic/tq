// Code generated by go-swagger; DO NOT EDIT.

package p_o_s_t

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

// CustomExecuteLocalProcedureWithMultipleResultSetsReader is a Reader for the CustomExecuteLocalProcedureWithMultipleResultSets structure.
type CustomExecuteLocalProcedureWithMultipleResultSetsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CustomExecuteLocalProcedureWithMultipleResultSetsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCustomExecuteLocalProcedureWithMultipleResultSetsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCustomExecuteLocalProcedureWithMultipleResultSetsDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCustomExecuteLocalProcedureWithMultipleResultSetsOK creates a CustomExecuteLocalProcedureWithMultipleResultSetsOK with default headers values
func NewCustomExecuteLocalProcedureWithMultipleResultSetsOK() *CustomExecuteLocalProcedureWithMultipleResultSetsOK {
	return &CustomExecuteLocalProcedureWithMultipleResultSetsOK{}
}

/*
CustomExecuteLocalProcedureWithMultipleResultSetsOK describes a response with status code 200, with default header values.

OK
*/
type CustomExecuteLocalProcedureWithMultipleResultSetsOK struct {
	Payload interface{}
}

// IsSuccess returns true when this custom execute local procedure with multiple result sets o k response has a 2xx status code
func (o *CustomExecuteLocalProcedureWithMultipleResultSetsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this custom execute local procedure with multiple result sets o k response has a 3xx status code
func (o *CustomExecuteLocalProcedureWithMultipleResultSetsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this custom execute local procedure with multiple result sets o k response has a 4xx status code
func (o *CustomExecuteLocalProcedureWithMultipleResultSetsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this custom execute local procedure with multiple result sets o k response has a 5xx status code
func (o *CustomExecuteLocalProcedureWithMultipleResultSetsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this custom execute local procedure with multiple result sets o k response a status code equal to that given
func (o *CustomExecuteLocalProcedureWithMultipleResultSetsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the custom execute local procedure with multiple result sets o k response
func (o *CustomExecuteLocalProcedureWithMultipleResultSetsOK) Code() int {
	return 200
}

func (o *CustomExecuteLocalProcedureWithMultipleResultSetsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Custom/Execute/MultipleResultSets][%d] customExecuteLocalProcedureWithMultipleResultSetsOK %s", 200, payload)
}

func (o *CustomExecuteLocalProcedureWithMultipleResultSetsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Custom/Execute/MultipleResultSets][%d] customExecuteLocalProcedureWithMultipleResultSetsOK %s", 200, payload)
}

func (o *CustomExecuteLocalProcedureWithMultipleResultSetsOK) GetPayload() interface{} {
	return o.Payload
}

func (o *CustomExecuteLocalProcedureWithMultipleResultSetsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCustomExecuteLocalProcedureWithMultipleResultSetsDefault creates a CustomExecuteLocalProcedureWithMultipleResultSetsDefault with default headers values
func NewCustomExecuteLocalProcedureWithMultipleResultSetsDefault(code int) *CustomExecuteLocalProcedureWithMultipleResultSetsDefault {
	return &CustomExecuteLocalProcedureWithMultipleResultSetsDefault{
		_statusCode: code,
	}
}

/*
CustomExecuteLocalProcedureWithMultipleResultSetsDefault describes a response with status code -1, with default header values.

Error
*/
type CustomExecuteLocalProcedureWithMultipleResultSetsDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this custom execute local procedure with multiple result sets default response has a 2xx status code
func (o *CustomExecuteLocalProcedureWithMultipleResultSetsDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this custom execute local procedure with multiple result sets default response has a 3xx status code
func (o *CustomExecuteLocalProcedureWithMultipleResultSetsDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this custom execute local procedure with multiple result sets default response has a 4xx status code
func (o *CustomExecuteLocalProcedureWithMultipleResultSetsDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this custom execute local procedure with multiple result sets default response has a 5xx status code
func (o *CustomExecuteLocalProcedureWithMultipleResultSetsDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this custom execute local procedure with multiple result sets default response a status code equal to that given
func (o *CustomExecuteLocalProcedureWithMultipleResultSetsDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the custom execute local procedure with multiple result sets default response
func (o *CustomExecuteLocalProcedureWithMultipleResultSetsDefault) Code() int {
	return o._statusCode
}

func (o *CustomExecuteLocalProcedureWithMultipleResultSetsDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Custom/Execute/MultipleResultSets][%d] Custom_ExecuteLocalProcedureWithMultipleResultSets default %s", o._statusCode, payload)
}

func (o *CustomExecuteLocalProcedureWithMultipleResultSetsDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Custom/Execute/MultipleResultSets][%d] Custom_ExecuteLocalProcedureWithMultipleResultSets default %s", o._statusCode, payload)
}

func (o *CustomExecuteLocalProcedureWithMultipleResultSetsDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CustomExecuteLocalProcedureWithMultipleResultSetsDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}