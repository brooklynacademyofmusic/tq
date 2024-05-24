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

// BulkCopySetsCopyEventReader is a Reader for the BulkCopySetsCopyEvent structure.
type BulkCopySetsCopyEventReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *BulkCopySetsCopyEventReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewBulkCopySetsCopyEventOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewBulkCopySetsCopyEventDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewBulkCopySetsCopyEventOK creates a BulkCopySetsCopyEventOK with default headers values
func NewBulkCopySetsCopyEventOK() *BulkCopySetsCopyEventOK {
	return &BulkCopySetsCopyEventOK{}
}

/*
BulkCopySetsCopyEventOK describes a response with status code 200, with default header values.

OK
*/
type BulkCopySetsCopyEventOK struct {
	Payload *models.PerformanceSummary
}

// IsSuccess returns true when this bulk copy sets copy event o k response has a 2xx status code
func (o *BulkCopySetsCopyEventOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this bulk copy sets copy event o k response has a 3xx status code
func (o *BulkCopySetsCopyEventOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this bulk copy sets copy event o k response has a 4xx status code
func (o *BulkCopySetsCopyEventOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this bulk copy sets copy event o k response has a 5xx status code
func (o *BulkCopySetsCopyEventOK) IsServerError() bool {
	return false
}

// IsCode returns true when this bulk copy sets copy event o k response a status code equal to that given
func (o *BulkCopySetsCopyEventOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the bulk copy sets copy event o k response
func (o *BulkCopySetsCopyEventOK) Code() int {
	return 200
}

func (o *BulkCopySetsCopyEventOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/BulkCopySets/{bulkCopySetId}/CopyEvent][%d] bulkCopySetsCopyEventOK %s", 200, payload)
}

func (o *BulkCopySetsCopyEventOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/BulkCopySets/{bulkCopySetId}/CopyEvent][%d] bulkCopySetsCopyEventOK %s", 200, payload)
}

func (o *BulkCopySetsCopyEventOK) GetPayload() *models.PerformanceSummary {
	return o.Payload
}

func (o *BulkCopySetsCopyEventOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PerformanceSummary)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewBulkCopySetsCopyEventDefault creates a BulkCopySetsCopyEventDefault with default headers values
func NewBulkCopySetsCopyEventDefault(code int) *BulkCopySetsCopyEventDefault {
	return &BulkCopySetsCopyEventDefault{
		_statusCode: code,
	}
}

/*
BulkCopySetsCopyEventDefault describes a response with status code -1, with default header values.

Error
*/
type BulkCopySetsCopyEventDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this bulk copy sets copy event default response has a 2xx status code
func (o *BulkCopySetsCopyEventDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this bulk copy sets copy event default response has a 3xx status code
func (o *BulkCopySetsCopyEventDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this bulk copy sets copy event default response has a 4xx status code
func (o *BulkCopySetsCopyEventDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this bulk copy sets copy event default response has a 5xx status code
func (o *BulkCopySetsCopyEventDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this bulk copy sets copy event default response a status code equal to that given
func (o *BulkCopySetsCopyEventDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the bulk copy sets copy event default response
func (o *BulkCopySetsCopyEventDefault) Code() int {
	return o._statusCode
}

func (o *BulkCopySetsCopyEventDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/BulkCopySets/{bulkCopySetId}/CopyEvent][%d] BulkCopySets_CopyEvent default %s", o._statusCode, payload)
}

func (o *BulkCopySetsCopyEventDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /TXN/BulkCopySets/{bulkCopySetId}/CopyEvent][%d] BulkCopySets_CopyEvent default %s", o._statusCode, payload)
}

func (o *BulkCopySetsCopyEventDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *BulkCopySetsCopyEventDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
