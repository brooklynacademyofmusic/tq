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

// GLAccountsGetSummariesReader is a Reader for the GLAccountsGetSummaries structure.
type GLAccountsGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GLAccountsGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGLAccountsGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /ReferenceData/GLAccounts/Summary] GLAccounts_GetSummaries", response, response.Code())
	}
}

// NewGLAccountsGetSummariesOK creates a GLAccountsGetSummariesOK with default headers values
func NewGLAccountsGetSummariesOK() *GLAccountsGetSummariesOK {
	return &GLAccountsGetSummariesOK{}
}

/*
GLAccountsGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type GLAccountsGetSummariesOK struct {
	Payload []*models.GlAccountSummary
}

// IsSuccess returns true when this g l accounts get summaries o k response has a 2xx status code
func (o *GLAccountsGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this g l accounts get summaries o k response has a 3xx status code
func (o *GLAccountsGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this g l accounts get summaries o k response has a 4xx status code
func (o *GLAccountsGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this g l accounts get summaries o k response has a 5xx status code
func (o *GLAccountsGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this g l accounts get summaries o k response a status code equal to that given
func (o *GLAccountsGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the g l accounts get summaries o k response
func (o *GLAccountsGetSummariesOK) Code() int {
	return 200
}

func (o *GLAccountsGetSummariesOK) Error() string {
	return fmt.Sprintf("[GET /ReferenceData/GLAccounts/Summary][%d] gLAccountsGetSummariesOK  %+v", 200, o.Payload)
}

func (o *GLAccountsGetSummariesOK) String() string {
	return fmt.Sprintf("[GET /ReferenceData/GLAccounts/Summary][%d] gLAccountsGetSummariesOK  %+v", 200, o.Payload)
}

func (o *GLAccountsGetSummariesOK) GetPayload() []*models.GlAccountSummary {
	return o.Payload
}

func (o *GLAccountsGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}