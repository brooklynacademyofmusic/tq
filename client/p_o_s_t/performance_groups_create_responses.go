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

// PerformanceGroupsCreateReader is a Reader for the PerformanceGroupsCreate structure.
type PerformanceGroupsCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PerformanceGroupsCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPerformanceGroupsCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /TXN/PerformanceGroups] PerformanceGroups_Create", response, response.Code())
	}
}

// NewPerformanceGroupsCreateOK creates a PerformanceGroupsCreateOK with default headers values
func NewPerformanceGroupsCreateOK() *PerformanceGroupsCreateOK {
	return &PerformanceGroupsCreateOK{}
}

/*
PerformanceGroupsCreateOK describes a response with status code 200, with default header values.

OK
*/
type PerformanceGroupsCreateOK struct {
	Payload *models.PerformanceGroup
}

// IsSuccess returns true when this performance groups create o k response has a 2xx status code
func (o *PerformanceGroupsCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this performance groups create o k response has a 3xx status code
func (o *PerformanceGroupsCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this performance groups create o k response has a 4xx status code
func (o *PerformanceGroupsCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this performance groups create o k response has a 5xx status code
func (o *PerformanceGroupsCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this performance groups create o k response a status code equal to that given
func (o *PerformanceGroupsCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the performance groups create o k response
func (o *PerformanceGroupsCreateOK) Code() int {
	return 200
}

func (o *PerformanceGroupsCreateOK) Error() string {
	return fmt.Sprintf("[POST /TXN/PerformanceGroups][%d] performanceGroupsCreateOK  %+v", 200, o.Payload)
}

func (o *PerformanceGroupsCreateOK) String() string {
	return fmt.Sprintf("[POST /TXN/PerformanceGroups][%d] performanceGroupsCreateOK  %+v", 200, o.Payload)
}

func (o *PerformanceGroupsCreateOK) GetPayload() *models.PerformanceGroup {
	return o.Payload
}

func (o *PerformanceGroupsCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PerformanceGroup)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}