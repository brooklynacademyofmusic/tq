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

// IssuesGetAllReader is a Reader for the IssuesGetAll structure.
type IssuesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *IssuesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewIssuesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /CRM/Issues] Issues_GetAll", response, response.Code())
	}
}

// NewIssuesGetAllOK creates a IssuesGetAllOK with default headers values
func NewIssuesGetAllOK() *IssuesGetAllOK {
	return &IssuesGetAllOK{}
}

/*
IssuesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type IssuesGetAllOK struct {
	Payload []*models.Issue
}

// IsSuccess returns true when this issues get all o k response has a 2xx status code
func (o *IssuesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this issues get all o k response has a 3xx status code
func (o *IssuesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this issues get all o k response has a 4xx status code
func (o *IssuesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this issues get all o k response has a 5xx status code
func (o *IssuesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this issues get all o k response a status code equal to that given
func (o *IssuesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the issues get all o k response
func (o *IssuesGetAllOK) Code() int {
	return 200
}

func (o *IssuesGetAllOK) Error() string {
	return fmt.Sprintf("[GET /CRM/Issues][%d] issuesGetAllOK  %+v", 200, o.Payload)
}

func (o *IssuesGetAllOK) String() string {
	return fmt.Sprintf("[GET /CRM/Issues][%d] issuesGetAllOK  %+v", 200, o.Payload)
}

func (o *IssuesGetAllOK) GetPayload() []*models.Issue {
	return o.Payload
}

func (o *IssuesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}