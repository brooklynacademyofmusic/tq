// Code generated by go-swagger; DO NOT EDIT.

package p_u_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// SurveyQuestionsUpdateReader is a Reader for the SurveyQuestionsUpdate structure.
type SurveyQuestionsUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SurveyQuestionsUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSurveyQuestionsUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[PUT /ReferenceData/SurveyQuestions/{id}] SurveyQuestions_Update", response, response.Code())
	}
}

// NewSurveyQuestionsUpdateOK creates a SurveyQuestionsUpdateOK with default headers values
func NewSurveyQuestionsUpdateOK() *SurveyQuestionsUpdateOK {
	return &SurveyQuestionsUpdateOK{}
}

/*
SurveyQuestionsUpdateOK describes a response with status code 200, with default header values.

OK
*/
type SurveyQuestionsUpdateOK struct {
	Payload *models.SurveyQuestion
}

// IsSuccess returns true when this survey questions update o k response has a 2xx status code
func (o *SurveyQuestionsUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this survey questions update o k response has a 3xx status code
func (o *SurveyQuestionsUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this survey questions update o k response has a 4xx status code
func (o *SurveyQuestionsUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this survey questions update o k response has a 5xx status code
func (o *SurveyQuestionsUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this survey questions update o k response a status code equal to that given
func (o *SurveyQuestionsUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the survey questions update o k response
func (o *SurveyQuestionsUpdateOK) Code() int {
	return 200
}

func (o *SurveyQuestionsUpdateOK) Error() string {
	return fmt.Sprintf("[PUT /ReferenceData/SurveyQuestions/{id}][%d] surveyQuestionsUpdateOK  %+v", 200, o.Payload)
}

func (o *SurveyQuestionsUpdateOK) String() string {
	return fmt.Sprintf("[PUT /ReferenceData/SurveyQuestions/{id}][%d] surveyQuestionsUpdateOK  %+v", 200, o.Payload)
}

func (o *SurveyQuestionsUpdateOK) GetPayload() *models.SurveyQuestion {
	return o.Payload
}

func (o *SurveyQuestionsUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.SurveyQuestion)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}