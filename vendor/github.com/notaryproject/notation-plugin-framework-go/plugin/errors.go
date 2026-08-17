// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugin

import (
	"encoding/json"
	"fmt"
)

type ErrorCode string

const (
	ErrorCodeValidation                 ErrorCode = "VALIDATION_ERROR"
	ErrorCodeUnsupportedContractVersion ErrorCode = "UNSUPPORTED_CONTRACT_VERSION"
	ErrorCodeAccessDenied               ErrorCode = "ACCESS_DENIED"
	ErrorCodeTimeout                    ErrorCode = "TIMEOUT"
	ErrorCodeThrottled                  ErrorCode = "THROTTLED"
	ErrorCodeGeneric                    ErrorCode = "ERROR"
)

const (
	ErrorMsgMalformedInput     string = "Input is not a valid JSON"
	ErrorMsgMalformedOutputFmt string = "Failed to generate response. Error: %s"
)

// Error is used to return a well-formed error response as per NotaryProject specification.
type Error struct {
	ErrCode  ErrorCode         `json:"errorCode"`
	Message  string            `json:"errorMessage,omitempty"`
	Metadata map[string]string `json:"errorMetadata,omitempty"`
}

func NewError(code ErrorCode, msg string) *Error {
	return &Error{
		ErrCode: code,
		Message: msg,
	}
}

func NewGenericError(msg string) *Error {
	return NewError(ErrorCodeGeneric, msg)
}

func NewGenericErrorf(format string, msg ...any) *Error {
	return NewError(ErrorCodeGeneric, fmt.Sprintf(format, msg...))
}

func NewUnsupportedError(msg string) *Error {
	return NewError(ErrorCodeValidation, msg+" is not supported")
}

func NewValidationError(msg string) *Error {
	return NewError(ErrorCodeValidation, msg)
}

func NewValidationErrorf(format string, msg ...any) *Error {
	return NewError(ErrorCodeValidation, fmt.Sprintf(format, msg...))
}

func NewUnsupportedContractVersionError(version string) *Error {
	return NewError(ErrorCodeUnsupportedContractVersion, fmt.Sprintf("%q is not a supported notary plugin contract version", version))
}

func NewJSONParsingError(msg string) *Error {
	return NewValidationError(msg)
}

// Error returns the formatted error message.
func (e *Error) Error() string {
	op, err := json.Marshal(e)
	if err != nil {
		return "something went wrong"
	}
	return string(op)
}
