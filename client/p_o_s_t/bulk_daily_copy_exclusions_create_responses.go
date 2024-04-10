// Code generated by go-swagger; DO NOT EDIT.

package p_o_s_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// BulkDailyCopyExclusionsCreateReader is a Reader for the BulkDailyCopyExclusionsCreate structure.
type BulkDailyCopyExclusionsCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *BulkDailyCopyExclusionsCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewBulkDailyCopyExclusionsCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /TXN/BulkDailyCopyExclusions] BulkDailyCopyExclusions_Create", response, response.Code())
	}
}

// NewBulkDailyCopyExclusionsCreateOK creates a BulkDailyCopyExclusionsCreateOK with default headers values
func NewBulkDailyCopyExclusionsCreateOK() *BulkDailyCopyExclusionsCreateOK {
	return &BulkDailyCopyExclusionsCreateOK{}
}

/*
BulkDailyCopyExclusionsCreateOK describes a response with status code 200, with default header values.

OK
*/
type BulkDailyCopyExclusionsCreateOK struct {
	Payload *models.BulkDailyCopyExclusion
}

// IsSuccess returns true when this bulk daily copy exclusions create o k response has a 2xx status code
func (o *BulkDailyCopyExclusionsCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this bulk daily copy exclusions create o k response has a 3xx status code
func (o *BulkDailyCopyExclusionsCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this bulk daily copy exclusions create o k response has a 4xx status code
func (o *BulkDailyCopyExclusionsCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this bulk daily copy exclusions create o k response has a 5xx status code
func (o *BulkDailyCopyExclusionsCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this bulk daily copy exclusions create o k response a status code equal to that given
func (o *BulkDailyCopyExclusionsCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the bulk daily copy exclusions create o k response
func (o *BulkDailyCopyExclusionsCreateOK) Code() int {
	return 200
}

func (o *BulkDailyCopyExclusionsCreateOK) Error() string {
	return fmt.Sprintf("[POST /TXN/BulkDailyCopyExclusions][%d] bulkDailyCopyExclusionsCreateOK  %+v", 200, o.Payload)
}

func (o *BulkDailyCopyExclusionsCreateOK) String() string {
	return fmt.Sprintf("[POST /TXN/BulkDailyCopyExclusions][%d] bulkDailyCopyExclusionsCreateOK  %+v", 200, o.Payload)
}

func (o *BulkDailyCopyExclusionsCreateOK) GetPayload() *models.BulkDailyCopyExclusion {
	return o.Payload
}

func (o *BulkDailyCopyExclusionsCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.BulkDailyCopyExclusion)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}