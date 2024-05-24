// Code generated by go-swagger; DO NOT EDIT.

package g_e_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// MembershipStandingsGetSummariesReader is a Reader for the MembershipStandingsGetSummaries structure.
type MembershipStandingsGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *MembershipStandingsGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewMembershipStandingsGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewMembershipStandingsGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewMembershipStandingsGetSummariesOK creates a MembershipStandingsGetSummariesOK with default headers values
func NewMembershipStandingsGetSummariesOK() *MembershipStandingsGetSummariesOK {
	return &MembershipStandingsGetSummariesOK{}
}

/*
MembershipStandingsGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type MembershipStandingsGetSummariesOK struct {
	Payload []*models.MembershipStandingSummary
}

// IsSuccess returns true when this membership standings get summaries o k response has a 2xx status code
func (o *MembershipStandingsGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this membership standings get summaries o k response has a 3xx status code
func (o *MembershipStandingsGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this membership standings get summaries o k response has a 4xx status code
func (o *MembershipStandingsGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this membership standings get summaries o k response has a 5xx status code
func (o *MembershipStandingsGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this membership standings get summaries o k response a status code equal to that given
func (o *MembershipStandingsGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the membership standings get summaries o k response
func (o *MembershipStandingsGetSummariesOK) Code() int {
	return 200
}

func (o *MembershipStandingsGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/MembershipStandings/Summary][%d] membershipStandingsGetSummariesOK %s", 200, payload)
}

func (o *MembershipStandingsGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/MembershipStandings/Summary][%d] membershipStandingsGetSummariesOK %s", 200, payload)
}

func (o *MembershipStandingsGetSummariesOK) GetPayload() []*models.MembershipStandingSummary {
	return o.Payload
}

func (o *MembershipStandingsGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewMembershipStandingsGetSummariesDefault creates a MembershipStandingsGetSummariesDefault with default headers values
func NewMembershipStandingsGetSummariesDefault(code int) *MembershipStandingsGetSummariesDefault {
	return &MembershipStandingsGetSummariesDefault{
		_statusCode: code,
	}
}

/*
MembershipStandingsGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type MembershipStandingsGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this membership standings get summaries default response has a 2xx status code
func (o *MembershipStandingsGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this membership standings get summaries default response has a 3xx status code
func (o *MembershipStandingsGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this membership standings get summaries default response has a 4xx status code
func (o *MembershipStandingsGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this membership standings get summaries default response has a 5xx status code
func (o *MembershipStandingsGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this membership standings get summaries default response a status code equal to that given
func (o *MembershipStandingsGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the membership standings get summaries default response
func (o *MembershipStandingsGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *MembershipStandingsGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/MembershipStandings/Summary][%d] MembershipStandings_GetSummaries default %s", o._statusCode, payload)
}

func (o *MembershipStandingsGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/MembershipStandings/Summary][%d] MembershipStandings_GetSummaries default %s", o._statusCode, payload)
}

func (o *MembershipStandingsGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *MembershipStandingsGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
