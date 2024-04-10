// Code generated by go-swagger; DO NOT EDIT.

package g_e_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// PlanSourcesGetAllReader is a Reader for the PlanSourcesGetAll structure.
type PlanSourcesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PlanSourcesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPlanSourcesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /ReferenceData/PlanSources] PlanSources_GetAll", response, response.Code())
	}
}

// NewPlanSourcesGetAllOK creates a PlanSourcesGetAllOK with default headers values
func NewPlanSourcesGetAllOK() *PlanSourcesGetAllOK {
	return &PlanSourcesGetAllOK{}
}

/*
PlanSourcesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type PlanSourcesGetAllOK struct {
	Payload []*models.PlanSource
}

// IsSuccess returns true when this plan sources get all o k response has a 2xx status code
func (o *PlanSourcesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this plan sources get all o k response has a 3xx status code
func (o *PlanSourcesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this plan sources get all o k response has a 4xx status code
func (o *PlanSourcesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this plan sources get all o k response has a 5xx status code
func (o *PlanSourcesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this plan sources get all o k response a status code equal to that given
func (o *PlanSourcesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the plan sources get all o k response
func (o *PlanSourcesGetAllOK) Code() int {
	return 200
}

func (o *PlanSourcesGetAllOK) Error() string {
	return fmt.Sprintf("[GET /ReferenceData/PlanSources][%d] planSourcesGetAllOK  %+v", 200, o.Payload)
}

func (o *PlanSourcesGetAllOK) String() string {
	return fmt.Sprintf("[GET /ReferenceData/PlanSources][%d] planSourcesGetAllOK  %+v", 200, o.Payload)
}

func (o *PlanSourcesGetAllOK) GetPayload() []*models.PlanSource {
	return o.Payload
}

func (o *PlanSourcesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}