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

// AuditLogsGetDetailsReader is a Reader for the AuditLogsGetDetails structure.
type AuditLogsGetDetailsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AuditLogsGetDetailsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAuditLogsGetDetailsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /Reporting/AuditLogs/Details] AuditLogs_GetDetails", response, response.Code())
	}
}

// NewAuditLogsGetDetailsOK creates a AuditLogsGetDetailsOK with default headers values
func NewAuditLogsGetDetailsOK() *AuditLogsGetDetailsOK {
	return &AuditLogsGetDetailsOK{}
}

/*
AuditLogsGetDetailsOK describes a response with status code 200, with default header values.

OK
*/
type AuditLogsGetDetailsOK struct {
	Payload []*models.AuditEntryDetail
}

// IsSuccess returns true when this audit logs get details o k response has a 2xx status code
func (o *AuditLogsGetDetailsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this audit logs get details o k response has a 3xx status code
func (o *AuditLogsGetDetailsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this audit logs get details o k response has a 4xx status code
func (o *AuditLogsGetDetailsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this audit logs get details o k response has a 5xx status code
func (o *AuditLogsGetDetailsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this audit logs get details o k response a status code equal to that given
func (o *AuditLogsGetDetailsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the audit logs get details o k response
func (o *AuditLogsGetDetailsOK) Code() int {
	return 200
}

func (o *AuditLogsGetDetailsOK) Error() string {
	return fmt.Sprintf("[GET /Reporting/AuditLogs/Details][%d] auditLogsGetDetailsOK  %+v", 200, o.Payload)
}

func (o *AuditLogsGetDetailsOK) String() string {
	return fmt.Sprintf("[GET /Reporting/AuditLogs/Details][%d] auditLogsGetDetailsOK  %+v", 200, o.Payload)
}

func (o *AuditLogsGetDetailsOK) GetPayload() []*models.AuditEntryDetail {
	return o.Payload
}

func (o *AuditLogsGetDetailsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}