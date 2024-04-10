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

// DocumentCategoriesGetAllReader is a Reader for the DocumentCategoriesGetAll structure.
type DocumentCategoriesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DocumentCategoriesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDocumentCategoriesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /ReferenceData/DocumentCategories] DocumentCategories_GetAll", response, response.Code())
	}
}

// NewDocumentCategoriesGetAllOK creates a DocumentCategoriesGetAllOK with default headers values
func NewDocumentCategoriesGetAllOK() *DocumentCategoriesGetAllOK {
	return &DocumentCategoriesGetAllOK{}
}

/*
DocumentCategoriesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type DocumentCategoriesGetAllOK struct {
	Payload []*models.DocumentCategory
}

// IsSuccess returns true when this document categories get all o k response has a 2xx status code
func (o *DocumentCategoriesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this document categories get all o k response has a 3xx status code
func (o *DocumentCategoriesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this document categories get all o k response has a 4xx status code
func (o *DocumentCategoriesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this document categories get all o k response has a 5xx status code
func (o *DocumentCategoriesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this document categories get all o k response a status code equal to that given
func (o *DocumentCategoriesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the document categories get all o k response
func (o *DocumentCategoriesGetAllOK) Code() int {
	return 200
}

func (o *DocumentCategoriesGetAllOK) Error() string {
	return fmt.Sprintf("[GET /ReferenceData/DocumentCategories][%d] documentCategoriesGetAllOK  %+v", 200, o.Payload)
}

func (o *DocumentCategoriesGetAllOK) String() string {
	return fmt.Sprintf("[GET /ReferenceData/DocumentCategories][%d] documentCategoriesGetAllOK  %+v", 200, o.Payload)
}

func (o *DocumentCategoriesGetAllOK) GetPayload() []*models.DocumentCategory {
	return o.Payload
}

func (o *DocumentCategoriesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}