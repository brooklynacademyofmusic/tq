// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// TemplatesDeleteReader is a Reader for the TemplatesDelete structure.
type TemplatesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TemplatesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewTemplatesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[DELETE /Templates/{templateId}] Templates_Delete", response, response.Code())
	}
}

// NewTemplatesDeleteNoContent creates a TemplatesDeleteNoContent with default headers values
func NewTemplatesDeleteNoContent() *TemplatesDeleteNoContent {
	return &TemplatesDeleteNoContent{}
}

/*
TemplatesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type TemplatesDeleteNoContent struct {
}

// IsSuccess returns true when this templates delete no content response has a 2xx status code
func (o *TemplatesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this templates delete no content response has a 3xx status code
func (o *TemplatesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this templates delete no content response has a 4xx status code
func (o *TemplatesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this templates delete no content response has a 5xx status code
func (o *TemplatesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this templates delete no content response a status code equal to that given
func (o *TemplatesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the templates delete no content response
func (o *TemplatesDeleteNoContent) Code() int {
	return 204
}

func (o *TemplatesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /Templates/{templateId}][%d] templatesDeleteNoContent ", 204)
}

func (o *TemplatesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /Templates/{templateId}][%d] templatesDeleteNoContent ", 204)
}

func (o *TemplatesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}