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

// IntegrationsGetSummariesReader is a Reader for the IntegrationsGetSummaries structure.
type IntegrationsGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *IntegrationsGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewIntegrationsGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /ReferenceData/Integrations/Summary] Integrations_GetSummaries", response, response.Code())
	}
}

// NewIntegrationsGetSummariesOK creates a IntegrationsGetSummariesOK with default headers values
func NewIntegrationsGetSummariesOK() *IntegrationsGetSummariesOK {
	return &IntegrationsGetSummariesOK{}
}

/*
IntegrationsGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type IntegrationsGetSummariesOK struct {
	Payload []*models.IntegrationSummary
}

// IsSuccess returns true when this integrations get summaries o k response has a 2xx status code
func (o *IntegrationsGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this integrations get summaries o k response has a 3xx status code
func (o *IntegrationsGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this integrations get summaries o k response has a 4xx status code
func (o *IntegrationsGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this integrations get summaries o k response has a 5xx status code
func (o *IntegrationsGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this integrations get summaries o k response a status code equal to that given
func (o *IntegrationsGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the integrations get summaries o k response
func (o *IntegrationsGetSummariesOK) Code() int {
	return 200
}

func (o *IntegrationsGetSummariesOK) Error() string {
	return fmt.Sprintf("[GET /ReferenceData/Integrations/Summary][%d] integrationsGetSummariesOK  %+v", 200, o.Payload)
}

func (o *IntegrationsGetSummariesOK) String() string {
	return fmt.Sprintf("[GET /ReferenceData/Integrations/Summary][%d] integrationsGetSummariesOK  %+v", 200, o.Payload)
}

func (o *IntegrationsGetSummariesOK) GetPayload() []*models.IntegrationSummary {
	return o.Payload
}

func (o *IntegrationsGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}