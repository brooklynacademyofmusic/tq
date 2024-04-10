// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// ConstituencyTypesDeleteReader is a Reader for the ConstituencyTypesDelete structure.
type ConstituencyTypesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ConstituencyTypesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewConstituencyTypesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[DELETE /ReferenceData/ConstituencyTypes/{id}] ConstituencyTypes_Delete", response, response.Code())
	}
}

// NewConstituencyTypesDeleteNoContent creates a ConstituencyTypesDeleteNoContent with default headers values
func NewConstituencyTypesDeleteNoContent() *ConstituencyTypesDeleteNoContent {
	return &ConstituencyTypesDeleteNoContent{}
}

/*
ConstituencyTypesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type ConstituencyTypesDeleteNoContent struct {
}

// IsSuccess returns true when this constituency types delete no content response has a 2xx status code
func (o *ConstituencyTypesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this constituency types delete no content response has a 3xx status code
func (o *ConstituencyTypesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this constituency types delete no content response has a 4xx status code
func (o *ConstituencyTypesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this constituency types delete no content response has a 5xx status code
func (o *ConstituencyTypesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this constituency types delete no content response a status code equal to that given
func (o *ConstituencyTypesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the constituency types delete no content response
func (o *ConstituencyTypesDeleteNoContent) Code() int {
	return 204
}

func (o *ConstituencyTypesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ConstituencyTypes/{id}][%d] constituencyTypesDeleteNoContent ", 204)
}

func (o *ConstituencyTypesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/ConstituencyTypes/{id}][%d] constituencyTypesDeleteNoContent ", 204)
}

func (o *ConstituencyTypesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}