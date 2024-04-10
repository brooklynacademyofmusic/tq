// Code generated by go-swagger; DO NOT EDIT.

package p_u_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// PlansUpdateReader is a Reader for the PlansUpdate structure.
type PlansUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PlansUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPlansUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[PUT /Finance/Plans/{planId}] Plans_Update", response, response.Code())
	}
}

// NewPlansUpdateOK creates a PlansUpdateOK with default headers values
func NewPlansUpdateOK() *PlansUpdateOK {
	return &PlansUpdateOK{}
}

/*
PlansUpdateOK describes a response with status code 200, with default header values.

OK
*/
type PlansUpdateOK struct {
	Payload *models.Plan
}

// IsSuccess returns true when this plans update o k response has a 2xx status code
func (o *PlansUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this plans update o k response has a 3xx status code
func (o *PlansUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this plans update o k response has a 4xx status code
func (o *PlansUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this plans update o k response has a 5xx status code
func (o *PlansUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this plans update o k response a status code equal to that given
func (o *PlansUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the plans update o k response
func (o *PlansUpdateOK) Code() int {
	return 200
}

func (o *PlansUpdateOK) Error() string {
	return fmt.Sprintf("[PUT /Finance/Plans/{planId}][%d] plansUpdateOK  %+v", 200, o.Payload)
}

func (o *PlansUpdateOK) String() string {
	return fmt.Sprintf("[PUT /Finance/Plans/{planId}][%d] plansUpdateOK  %+v", 200, o.Payload)
}

func (o *PlansUpdateOK) GetPayload() *models.Plan {
	return o.Payload
}

func (o *PlansUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Plan)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}