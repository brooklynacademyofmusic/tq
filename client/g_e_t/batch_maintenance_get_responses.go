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

// BatchMaintenanceGetReader is a Reader for the BatchMaintenanceGet structure.
type BatchMaintenanceGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *BatchMaintenanceGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewBatchMaintenanceGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewBatchMaintenanceGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewBatchMaintenanceGetOK creates a BatchMaintenanceGetOK with default headers values
func NewBatchMaintenanceGetOK() *BatchMaintenanceGetOK {
	return &BatchMaintenanceGetOK{}
}

/*
BatchMaintenanceGetOK describes a response with status code 200, with default header values.

OK
*/
type BatchMaintenanceGetOK struct {
	Payload *models.Batch
}

// IsSuccess returns true when this batch maintenance get o k response has a 2xx status code
func (o *BatchMaintenanceGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this batch maintenance get o k response has a 3xx status code
func (o *BatchMaintenanceGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this batch maintenance get o k response has a 4xx status code
func (o *BatchMaintenanceGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this batch maintenance get o k response has a 5xx status code
func (o *BatchMaintenanceGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this batch maintenance get o k response a status code equal to that given
func (o *BatchMaintenanceGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the batch maintenance get o k response
func (o *BatchMaintenanceGetOK) Code() int {
	return 200
}

func (o *BatchMaintenanceGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/BatchMaintenance/{batchId}][%d] batchMaintenanceGetOK %s", 200, payload)
}

func (o *BatchMaintenanceGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/BatchMaintenance/{batchId}][%d] batchMaintenanceGetOK %s", 200, payload)
}

func (o *BatchMaintenanceGetOK) GetPayload() *models.Batch {
	return o.Payload
}

func (o *BatchMaintenanceGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Batch)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewBatchMaintenanceGetDefault creates a BatchMaintenanceGetDefault with default headers values
func NewBatchMaintenanceGetDefault(code int) *BatchMaintenanceGetDefault {
	return &BatchMaintenanceGetDefault{
		_statusCode: code,
	}
}

/*
BatchMaintenanceGetDefault describes a response with status code -1, with default header values.

Error
*/
type BatchMaintenanceGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this batch maintenance get default response has a 2xx status code
func (o *BatchMaintenanceGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this batch maintenance get default response has a 3xx status code
func (o *BatchMaintenanceGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this batch maintenance get default response has a 4xx status code
func (o *BatchMaintenanceGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this batch maintenance get default response has a 5xx status code
func (o *BatchMaintenanceGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this batch maintenance get default response a status code equal to that given
func (o *BatchMaintenanceGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the batch maintenance get default response
func (o *BatchMaintenanceGetDefault) Code() int {
	return o._statusCode
}

func (o *BatchMaintenanceGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/BatchMaintenance/{batchId}][%d] BatchMaintenance_Get default %s", o._statusCode, payload)
}

func (o *BatchMaintenanceGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/BatchMaintenance/{batchId}][%d] BatchMaintenance_Get default %s", o._statusCode, payload)
}

func (o *BatchMaintenanceGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *BatchMaintenanceGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}