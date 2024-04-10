// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// NameStatusesDeleteReader is a Reader for the NameStatusesDelete structure.
type NameStatusesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *NameStatusesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewNameStatusesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[DELETE /ReferenceData/NameStatuses/{id}] NameStatuses_Delete", response, response.Code())
	}
}

// NewNameStatusesDeleteNoContent creates a NameStatusesDeleteNoContent with default headers values
func NewNameStatusesDeleteNoContent() *NameStatusesDeleteNoContent {
	return &NameStatusesDeleteNoContent{}
}

/*
NameStatusesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type NameStatusesDeleteNoContent struct {
}

// IsSuccess returns true when this name statuses delete no content response has a 2xx status code
func (o *NameStatusesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this name statuses delete no content response has a 3xx status code
func (o *NameStatusesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this name statuses delete no content response has a 4xx status code
func (o *NameStatusesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this name statuses delete no content response has a 5xx status code
func (o *NameStatusesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this name statuses delete no content response a status code equal to that given
func (o *NameStatusesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the name statuses delete no content response
func (o *NameStatusesDeleteNoContent) Code() int {
	return 204
}

func (o *NameStatusesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/NameStatuses/{id}][%d] nameStatusesDeleteNoContent ", 204)
}

func (o *NameStatusesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/NameStatuses/{id}][%d] nameStatusesDeleteNoContent ", 204)
}

func (o *NameStatusesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}