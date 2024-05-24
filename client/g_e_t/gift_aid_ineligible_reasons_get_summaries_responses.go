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

// GiftAidIneligibleReasonsGetSummariesReader is a Reader for the GiftAidIneligibleReasonsGetSummaries structure.
type GiftAidIneligibleReasonsGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GiftAidIneligibleReasonsGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGiftAidIneligibleReasonsGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewGiftAidIneligibleReasonsGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewGiftAidIneligibleReasonsGetSummariesOK creates a GiftAidIneligibleReasonsGetSummariesOK with default headers values
func NewGiftAidIneligibleReasonsGetSummariesOK() *GiftAidIneligibleReasonsGetSummariesOK {
	return &GiftAidIneligibleReasonsGetSummariesOK{}
}

/*
GiftAidIneligibleReasonsGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type GiftAidIneligibleReasonsGetSummariesOK struct {
	Payload []*models.GiftAidIneligibleReasonSummary
}

// IsSuccess returns true when this gift aid ineligible reasons get summaries o k response has a 2xx status code
func (o *GiftAidIneligibleReasonsGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this gift aid ineligible reasons get summaries o k response has a 3xx status code
func (o *GiftAidIneligibleReasonsGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this gift aid ineligible reasons get summaries o k response has a 4xx status code
func (o *GiftAidIneligibleReasonsGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this gift aid ineligible reasons get summaries o k response has a 5xx status code
func (o *GiftAidIneligibleReasonsGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this gift aid ineligible reasons get summaries o k response a status code equal to that given
func (o *GiftAidIneligibleReasonsGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the gift aid ineligible reasons get summaries o k response
func (o *GiftAidIneligibleReasonsGetSummariesOK) Code() int {
	return 200
}

func (o *GiftAidIneligibleReasonsGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/GiftAidIneligibleReasons/Summary][%d] giftAidIneligibleReasonsGetSummariesOK %s", 200, payload)
}

func (o *GiftAidIneligibleReasonsGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/GiftAidIneligibleReasons/Summary][%d] giftAidIneligibleReasonsGetSummariesOK %s", 200, payload)
}

func (o *GiftAidIneligibleReasonsGetSummariesOK) GetPayload() []*models.GiftAidIneligibleReasonSummary {
	return o.Payload
}

func (o *GiftAidIneligibleReasonsGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGiftAidIneligibleReasonsGetSummariesDefault creates a GiftAidIneligibleReasonsGetSummariesDefault with default headers values
func NewGiftAidIneligibleReasonsGetSummariesDefault(code int) *GiftAidIneligibleReasonsGetSummariesDefault {
	return &GiftAidIneligibleReasonsGetSummariesDefault{
		_statusCode: code,
	}
}

/*
GiftAidIneligibleReasonsGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type GiftAidIneligibleReasonsGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this gift aid ineligible reasons get summaries default response has a 2xx status code
func (o *GiftAidIneligibleReasonsGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this gift aid ineligible reasons get summaries default response has a 3xx status code
func (o *GiftAidIneligibleReasonsGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this gift aid ineligible reasons get summaries default response has a 4xx status code
func (o *GiftAidIneligibleReasonsGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this gift aid ineligible reasons get summaries default response has a 5xx status code
func (o *GiftAidIneligibleReasonsGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this gift aid ineligible reasons get summaries default response a status code equal to that given
func (o *GiftAidIneligibleReasonsGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the gift aid ineligible reasons get summaries default response
func (o *GiftAidIneligibleReasonsGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *GiftAidIneligibleReasonsGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/GiftAidIneligibleReasons/Summary][%d] GiftAidIneligibleReasons_GetSummaries default %s", o._statusCode, payload)
}

func (o *GiftAidIneligibleReasonsGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/GiftAidIneligibleReasons/Summary][%d] GiftAidIneligibleReasons_GetSummaries default %s", o._statusCode, payload)
}

func (o *GiftAidIneligibleReasonsGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *GiftAidIneligibleReasonsGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
