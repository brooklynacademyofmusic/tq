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

// BulkCopySetsGetReader is a Reader for the BulkCopySetsGet structure.
type BulkCopySetsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *BulkCopySetsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewBulkCopySetsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewBulkCopySetsGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewBulkCopySetsGetOK creates a BulkCopySetsGetOK with default headers values
func NewBulkCopySetsGetOK() *BulkCopySetsGetOK {
	return &BulkCopySetsGetOK{}
}

/*
BulkCopySetsGetOK describes a response with status code 200, with default header values.

OK
*/
type BulkCopySetsGetOK struct {
	Payload *models.BulkCopySet
}

// IsSuccess returns true when this bulk copy sets get o k response has a 2xx status code
func (o *BulkCopySetsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this bulk copy sets get o k response has a 3xx status code
func (o *BulkCopySetsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this bulk copy sets get o k response has a 4xx status code
func (o *BulkCopySetsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this bulk copy sets get o k response has a 5xx status code
func (o *BulkCopySetsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this bulk copy sets get o k response a status code equal to that given
func (o *BulkCopySetsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the bulk copy sets get o k response
func (o *BulkCopySetsGetOK) Code() int {
	return 200
}

func (o *BulkCopySetsGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/BulkCopySets/{bulkCopySetId}][%d] bulkCopySetsGetOK %s", 200, payload)
}

func (o *BulkCopySetsGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/BulkCopySets/{bulkCopySetId}][%d] bulkCopySetsGetOK %s", 200, payload)
}

func (o *BulkCopySetsGetOK) GetPayload() *models.BulkCopySet {
	return o.Payload
}

func (o *BulkCopySetsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BulkCopySet)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewBulkCopySetsGetDefault creates a BulkCopySetsGetDefault with default headers values
func NewBulkCopySetsGetDefault(code int) *BulkCopySetsGetDefault {
	return &BulkCopySetsGetDefault{
		_statusCode: code,
	}
}

/*
BulkCopySetsGetDefault describes a response with status code -1, with default header values.

Error
*/
type BulkCopySetsGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this bulk copy sets get default response has a 2xx status code
func (o *BulkCopySetsGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this bulk copy sets get default response has a 3xx status code
func (o *BulkCopySetsGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this bulk copy sets get default response has a 4xx status code
func (o *BulkCopySetsGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this bulk copy sets get default response has a 5xx status code
func (o *BulkCopySetsGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this bulk copy sets get default response a status code equal to that given
func (o *BulkCopySetsGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the bulk copy sets get default response
func (o *BulkCopySetsGetDefault) Code() int {
	return o._statusCode
}

func (o *BulkCopySetsGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/BulkCopySets/{bulkCopySetId}][%d] BulkCopySets_Get default %s", o._statusCode, payload)
}

func (o *BulkCopySetsGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/BulkCopySets/{bulkCopySetId}][%d] BulkCopySets_Get default %s", o._statusCode, payload)
}

func (o *BulkCopySetsGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *BulkCopySetsGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
