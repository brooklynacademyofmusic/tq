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

// ContributionImportSetsGetSummariesReader is a Reader for the ContributionImportSetsGetSummaries structure.
type ContributionImportSetsGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ContributionImportSetsGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewContributionImportSetsGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /ReferenceData/ContributionImportSets/Summary] ContributionImportSets_GetSummaries", response, response.Code())
	}
}

// NewContributionImportSetsGetSummariesOK creates a ContributionImportSetsGetSummariesOK with default headers values
func NewContributionImportSetsGetSummariesOK() *ContributionImportSetsGetSummariesOK {
	return &ContributionImportSetsGetSummariesOK{}
}

/*
ContributionImportSetsGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type ContributionImportSetsGetSummariesOK struct {
	Payload []*models.ContributionImportSetSummary
}

// IsSuccess returns true when this contribution import sets get summaries o k response has a 2xx status code
func (o *ContributionImportSetsGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this contribution import sets get summaries o k response has a 3xx status code
func (o *ContributionImportSetsGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this contribution import sets get summaries o k response has a 4xx status code
func (o *ContributionImportSetsGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this contribution import sets get summaries o k response has a 5xx status code
func (o *ContributionImportSetsGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this contribution import sets get summaries o k response a status code equal to that given
func (o *ContributionImportSetsGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the contribution import sets get summaries o k response
func (o *ContributionImportSetsGetSummariesOK) Code() int {
	return 200
}

func (o *ContributionImportSetsGetSummariesOK) Error() string {
	return fmt.Sprintf("[GET /ReferenceData/ContributionImportSets/Summary][%d] contributionImportSetsGetSummariesOK  %+v", 200, o.Payload)
}

func (o *ContributionImportSetsGetSummariesOK) String() string {
	return fmt.Sprintf("[GET /ReferenceData/ContributionImportSets/Summary][%d] contributionImportSetsGetSummariesOK  %+v", 200, o.Payload)
}

func (o *ContributionImportSetsGetSummariesOK) GetPayload() []*models.ContributionImportSetSummary {
	return o.Payload
}

func (o *ContributionImportSetsGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}