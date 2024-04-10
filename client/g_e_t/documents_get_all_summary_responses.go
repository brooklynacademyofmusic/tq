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

// DocumentsGetAllSummaryReader is a Reader for the DocumentsGetAllSummary structure.
type DocumentsGetAllSummaryReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DocumentsGetAllSummaryReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDocumentsGetAllSummaryOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /Finance/Documents/Summary] Documents_GetAllSummary", response, response.Code())
	}
}

// NewDocumentsGetAllSummaryOK creates a DocumentsGetAllSummaryOK with default headers values
func NewDocumentsGetAllSummaryOK() *DocumentsGetAllSummaryOK {
	return &DocumentsGetAllSummaryOK{}
}

/*
DocumentsGetAllSummaryOK describes a response with status code 200, with default header values.

OK
*/
type DocumentsGetAllSummaryOK struct {
	Payload []*models.DocumentSummary
}

// IsSuccess returns true when this documents get all summary o k response has a 2xx status code
func (o *DocumentsGetAllSummaryOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this documents get all summary o k response has a 3xx status code
func (o *DocumentsGetAllSummaryOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this documents get all summary o k response has a 4xx status code
func (o *DocumentsGetAllSummaryOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this documents get all summary o k response has a 5xx status code
func (o *DocumentsGetAllSummaryOK) IsServerError() bool {
	return false
}

// IsCode returns true when this documents get all summary o k response a status code equal to that given
func (o *DocumentsGetAllSummaryOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the documents get all summary o k response
func (o *DocumentsGetAllSummaryOK) Code() int {
	return 200
}

func (o *DocumentsGetAllSummaryOK) Error() string {
	return fmt.Sprintf("[GET /Finance/Documents/Summary][%d] documentsGetAllSummaryOK  %+v", 200, o.Payload)
}

func (o *DocumentsGetAllSummaryOK) String() string {
	return fmt.Sprintf("[GET /Finance/Documents/Summary][%d] documentsGetAllSummaryOK  %+v", 200, o.Payload)
}

func (o *DocumentsGetAllSummaryOK) GetPayload() []*models.DocumentSummary {
	return o.Payload
}

func (o *DocumentsGetAllSummaryOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}