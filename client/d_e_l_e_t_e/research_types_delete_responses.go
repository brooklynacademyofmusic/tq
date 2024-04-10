// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// ResearchTypesDeleteReader is a Reader for the ResearchTypesDelete structure.
type ResearchTypesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ResearchTypesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewResearchTypesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[DELETE /ReferenceData/ResearchTypes/{id}] ResearchTypes_Delete", response, response.Code())
	}
}

// NewResearchTypesDeleteNoContent creates a ResearchTypesDeleteNoContent with default headers values
func NewResearchTypesDeleteNoContent() *ResearchTypesDeleteNoContent {
	return &ResearchTypesDeleteNoContent{}
}

/*
ResearchTypesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type ResearchTypesDeleteNoContent struct {
}

// IsSuccess returns true when this research types delete no content response has a 2xx status code
func (o *ResearchTypesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this research types delete no content response has a 3xx status code
func (o *ResearchTypesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this research types delete no content response has a 4xx status code
func (o *ResearchTypesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this research types delete no content response has a 5xx status code
func (o *ResearchTypesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this research types delete no content response a status code equal to that given
func (o *ResearchTypesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the research types delete no content response
func (o *ResearchTypesDeleteNoContent) Code() int {
	return 204
}

func (o *ResearchTypesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ResearchTypes/{id}][%d] researchTypesDeleteNoContent ", 204)
}

func (o *ResearchTypesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ResearchTypes/{id}][%d] researchTypesDeleteNoContent ", 204)
}

func (o *ResearchTypesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}