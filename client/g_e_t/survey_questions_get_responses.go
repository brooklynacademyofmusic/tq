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

// SurveyQuestionsGetReader is a Reader for the SurveyQuestionsGet structure.
type SurveyQuestionsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SurveyQuestionsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSurveyQuestionsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSurveyQuestionsGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSurveyQuestionsGetOK creates a SurveyQuestionsGetOK with default headers values
func NewSurveyQuestionsGetOK() *SurveyQuestionsGetOK {
	return &SurveyQuestionsGetOK{}
}

/*
SurveyQuestionsGetOK describes a response with status code 200, with default header values.

OK
*/
type SurveyQuestionsGetOK struct {
	Payload *models.SurveyQuestion
}

// IsSuccess returns true when this survey questions get o k response has a 2xx status code
func (o *SurveyQuestionsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this survey questions get o k response has a 3xx status code
func (o *SurveyQuestionsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this survey questions get o k response has a 4xx status code
func (o *SurveyQuestionsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this survey questions get o k response has a 5xx status code
func (o *SurveyQuestionsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this survey questions get o k response a status code equal to that given
func (o *SurveyQuestionsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the survey questions get o k response
func (o *SurveyQuestionsGetOK) Code() int {
	return 200
}

func (o *SurveyQuestionsGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SurveyQuestions/{id}][%d] surveyQuestionsGetOK %s", 200, payload)
}

func (o *SurveyQuestionsGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SurveyQuestions/{id}][%d] surveyQuestionsGetOK %s", 200, payload)
}

func (o *SurveyQuestionsGetOK) GetPayload() *models.SurveyQuestion {
	return o.Payload
}

func (o *SurveyQuestionsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SurveyQuestion)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSurveyQuestionsGetDefault creates a SurveyQuestionsGetDefault with default headers values
func NewSurveyQuestionsGetDefault(code int) *SurveyQuestionsGetDefault {
	return &SurveyQuestionsGetDefault{
		_statusCode: code,
	}
}

/*
SurveyQuestionsGetDefault describes a response with status code -1, with default header values.

Error
*/
type SurveyQuestionsGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this survey questions get default response has a 2xx status code
func (o *SurveyQuestionsGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this survey questions get default response has a 3xx status code
func (o *SurveyQuestionsGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this survey questions get default response has a 4xx status code
func (o *SurveyQuestionsGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this survey questions get default response has a 5xx status code
func (o *SurveyQuestionsGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this survey questions get default response a status code equal to that given
func (o *SurveyQuestionsGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the survey questions get default response
func (o *SurveyQuestionsGetDefault) Code() int {
	return o._statusCode
}

func (o *SurveyQuestionsGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SurveyQuestions/{id}][%d] SurveyQuestions_Get default %s", o._statusCode, payload)
}

func (o *SurveyQuestionsGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SurveyQuestions/{id}][%d] SurveyQuestions_Get default %s", o._statusCode, payload)
}

func (o *SurveyQuestionsGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SurveyQuestionsGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}