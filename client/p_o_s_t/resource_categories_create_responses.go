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

// ResourceCategoriesCreateReader is a Reader for the ResourceCategoriesCreate structure.
type ResourceCategoriesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ResourceCategoriesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewResourceCategoriesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /ReferenceData/ResourceCategories] ResourceCategories_Create", response, response.Code())
	}
}

// NewResourceCategoriesCreateOK creates a ResourceCategoriesCreateOK with default headers values
func NewResourceCategoriesCreateOK() *ResourceCategoriesCreateOK {
	return &ResourceCategoriesCreateOK{}
}

/*
ResourceCategoriesCreateOK describes a response with status code 200, with default header values.

OK
*/
type ResourceCategoriesCreateOK struct {
	Payload *models.ResourceCategory
}

// IsSuccess returns true when this resource categories create o k response has a 2xx status code
func (o *ResourceCategoriesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this resource categories create o k response has a 3xx status code
func (o *ResourceCategoriesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this resource categories create o k response has a 4xx status code
func (o *ResourceCategoriesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this resource categories create o k response has a 5xx status code
func (o *ResourceCategoriesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this resource categories create o k response a status code equal to that given
func (o *ResourceCategoriesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the resource categories create o k response
func (o *ResourceCategoriesCreateOK) Code() int {
	return 200
}

func (o *ResourceCategoriesCreateOK) Error() string {
	return fmt.Sprintf("[POST /ReferenceData/ResourceCategories][%d] resourceCategoriesCreateOK  %+v", 200, o.Payload)
}

func (o *ResourceCategoriesCreateOK) String() string {
	return fmt.Sprintf("[POST /ReferenceData/ResourceCategories][%d] resourceCategoriesCreateOK  %+v", 200, o.Payload)
}

func (o *ResourceCategoriesCreateOK) GetPayload() *models.ResourceCategory {
	return o.Payload
}

func (o *ResourceCategoriesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResourceCategory)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}