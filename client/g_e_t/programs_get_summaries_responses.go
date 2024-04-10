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

// ProgramsGetSummariesReader is a Reader for the ProgramsGetSummaries structure.
type ProgramsGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ProgramsGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewProgramsGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /ReferenceData/Programs/Summary] Programs_GetSummaries", response, response.Code())
	}
}

// NewProgramsGetSummariesOK creates a ProgramsGetSummariesOK with default headers values
func NewProgramsGetSummariesOK() *ProgramsGetSummariesOK {
	return &ProgramsGetSummariesOK{}
}

/*
ProgramsGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type ProgramsGetSummariesOK struct {
	Payload []*models.ProgramSummary
}

// IsSuccess returns true when this programs get summaries o k response has a 2xx status code
func (o *ProgramsGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this programs get summaries o k response has a 3xx status code
func (o *ProgramsGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this programs get summaries o k response has a 4xx status code
func (o *ProgramsGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this programs get summaries o k response has a 5xx status code
func (o *ProgramsGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this programs get summaries o k response a status code equal to that given
func (o *ProgramsGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the programs get summaries o k response
func (o *ProgramsGetSummariesOK) Code() int {
	return 200
}

func (o *ProgramsGetSummariesOK) Error() string {
	return fmt.Sprintf("[GET /ReferenceData/Programs/Summary][%d] programsGetSummariesOK  %+v", 200, o.Payload)
}

func (o *ProgramsGetSummariesOK) String() string {
	return fmt.Sprintf("[GET /ReferenceData/Programs/Summary][%d] programsGetSummariesOK  %+v", 200, o.Payload)
}

func (o *ProgramsGetSummariesOK) GetPayload() []*models.ProgramSummary {
	return o.Payload
}

func (o *ProgramsGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}