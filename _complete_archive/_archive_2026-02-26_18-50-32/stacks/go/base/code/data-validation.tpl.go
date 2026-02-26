// File: data-validation.tpl.go
// Purpose: Template for unknown implementation
// Generated for: {{PROJECT_NAME}}

// -----------------------------------------------------------------------------
// FILE: data-validation.tpl.go
// PURPOSE: Comprehensive data validation utilities for Go projects
// USAGE: Import and adapt for consistent data validation across the application
// DEPENDENCIES: encoding/json, fmt, reflect, regexp, strconv, strings, time
// AUTHOR: [[.Author]]
// VERSION: [[.Version]]
// SINCE: [[.Version]]
// -----------------------------------------------------------------------------

package validation

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ValidationType represents the type of validation
type ValidationType string

const (
	TypeRequired    ValidationType = "required"
	TypeString      ValidationType = "string"
	TypeEmail       ValidationType = "email"
	TypePhone       ValidationType = "phone"
	TypeURL         ValidationType = "url"
	TypeNumber      ValidationType = "number"
	TypeInteger     ValidationType = "integer"
	TypeMin         ValidationType = "min"
	TypeMax         ValidationType = "max"
	TypeMinLength   ValidationType = "min_length"
	TypeMaxLength   ValidationType = "max_length"
	TypePattern     ValidationType = "pattern"
	TypeCustom      ValidationType = "custom"
	TypeChoices     ValidationType = "choices"
	TypeDate        ValidationType = "date"
	TypeDateTime    ValidationType = "datetime"
)

// ValidationRule represents a validation rule
type ValidationRule struct {
	Type         ValidationType `json:"type"`
	Params       map[string]interface{} `json:"params"`
	ErrorMessage string         `json:"error_message"`
}

// NewValidationRule creates a new validation rule
func NewValidationRule(validationType ValidationType, params map[string]interface{}, message string) *ValidationRule {
	return &ValidationRule{
		Type:         validationType,
		Params:       params,
		ErrorMessage: message,
	}
}

// Default error messages
var defaultErrorMessages = map[ValidationType]string{
	TypeRequired:    "This field is required",
	TypeEmail:       "Please enter a valid email address",
	TypePhone:       "Please enter a valid phone number",
	TypeURL:         "Please enter a valid URL",
	TypeNumber:      "Please enter a valid number",
	TypeInteger:     "Please enter a valid integer",
	TypeMin:         "Value must be at least %v",
	TypeMax:         "Value must be at most %v",
	TypeMinLength:   "Must be at least %v characters",
	TypeMaxLength:   "Must be at most %v characters",
	TypePattern:     "Invalid format",
	TypeCustom:      "Invalid input",
	TypeChoices:     "Must be one of: %v",
	TypeDate:        "Please enter a valid date",
	TypeDateTime:    "Please enter a valid datetime",
}

// GetErrorMessage returns the error message for the rule
func (r *ValidationRule) GetErrorMessage() string {
	if r.ErrorMessage != "" {
		return r.ErrorMessage
	}
	
	if msg, exists := defaultErrorMessages[r.Type]; exists {
		if strings.Contains(msg, "%v") && r.Params != nil {
			if value, ok := r.Params["value"]; ok {
				return fmt.Sprintf(msg, value)
			}
			if length, ok := r.Params["length"]; ok {
				return fmt.Sprintf(msg, length)
			}
			if choices, ok := r.Params["choices"]; ok {
				return fmt.Sprintf(msg, choices)
			}
		}
		return msg
	}
	
	return "Invalid input"
}

// ValidationResult represents the result of a validation
type ValidationResult struct {
	Field   string   `json:"field"`
	Value   interface{} `json:"value"`
	IsValid bool     `json:"is_valid"`
	Errors  []string `json:"errors"`
}

// NewValidationResult creates a new validation result
func NewValidationResult(field string, value interface{}) *ValidationResult {
	return &ValidationResult{
		Field:   field,
		Value:   value,
		IsValid: true,
		Errors:  make([]string, 0),
	}
}

// AddError adds an error to the validation result
func (r *ValidationResult) AddError(message string) {
	r.IsValid = false
	r.Errors = append(r.Errors, message)
}

// GetFirstError returns the first error message
func (r *ValidationResult) GetFirstError() string {
	if len(r.Errors) > 0 {
		return r.Errors[0]
	}
	return ""
}

// FormValidationResult represents the result of form validation
type FormValidationResult struct {
	IsValid     bool                         `json:"is_valid"`
	FieldResults map[string]*ValidationResult `json:"field_results"`
}

// NewFormValidationResult creates a new form validation result
func NewFormValidationResult() *FormValidationResult {
	return &FormValidationResult{
		IsValid:     true,
		FieldResults: make(map[string]*ValidationResult),
	}
}

// AddFieldResult adds a field validation result
func (r *FormValidationResult) AddFieldResult(fieldName string, result *ValidationResult) {
	r.FieldResults[fieldName] = result
	if !result.IsValid {
		r.IsValid = false
	}
}

// GetAllErrors returns all errors from all fields
func (r *FormValidationResult) GetAllErrors() []string {
	var allErrors []string
	for _, result := range r.FieldResults {
		allErrors = append(allErrors, result.Errors...)
	}
	return allErrors
}

// GetFieldErrors returns errors for a specific field
func (r *FormValidationResult) GetFieldErrors(fieldName string) []string {
	if result, exists := r.FieldResults[fieldName]; exists {
		return result.Errors
	}
	return []string{}
}

// IsFieldValid checks if a field is valid
func (r *FormValidationResult) IsFieldValid(fieldName string) bool {
	if result, exists := r.FieldResults[fieldName]; exists {
		return result.IsValid
	}
	return true
}

// Validator represents a data validator
type Validator struct {
	rules map[string][]*ValidationRule
	customValidators map[string]func(interface{}) bool
}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{
		rules: make(map[string][]*ValidationRule),
		customValidators: make(map[string]func(interface{}) bool),
	}
}

// AddRule adds a validation rule for a field
func (v *Validator) AddRule(fieldName string, rule *ValidationRule) {
	if v.rules[fieldName] == nil {
		v.rules[fieldName] = make([]*ValidationRule, 0)
	}
	v.rules[fieldName] = append(v.rules[fieldName], rule)
}

// AddRules adds multiple validation rules for a field
func (v *Validator) AddRules(fieldName string, rules []*ValidationRule) {
	if v.rules[fieldName] == nil {
		v.rules[fieldName] = make([]*ValidationRule, 0)
	}
	v.rules[fieldName] = append(v.rules[fieldName], rules...)
}

// AddCustomValidator adds a custom validator function
func (v *Validator) AddCustomValidator(name string, validator func(interface{}) bool) {
	v.customValidators[name] = validator
}

// ValidateField validates a single field
func (v *Validator) ValidateField(fieldName string, value interface{}) *ValidationResult {
	result := NewValidationResult(fieldName, value)
	rules := v.rules[fieldName]
	
	for _, rule := range rules {
		if err := v.validateRule(rule, value); err != "" {
			result.AddError(err)
		}
	}
	
	return result
}

// Validate validates an entire data structure
func (v *Validator) Validate(data map[string]interface{}) *FormValidationResult {
	formResult := NewFormValidationResult()
	
	for fieldName := range v.rules {
		value := data[fieldName]
		fieldResult := v.ValidateField(fieldName, value)
		formResult.AddFieldResult(fieldName, fieldResult)
	}
	
	return formResult
}

// validateRule validates a single rule against a value
func (v *Validator) validateRule(rule *ValidationRule, value interface{}) string {
	switch rule.Type {
	case TypeRequired:
		return v.validateRequired(value)
	case TypeString:
		return v.validateString(value)
	case TypeEmail:
		return v.validateEmail(value)
	case TypePhone:
		return v.validatePhone(value)
	case TypeURL:
		return v.validateURL(value)
	case TypeNumber:
		return v.validateNumber(value)
	case TypeInteger:
		return v.validateInteger(value)
	case TypeMin:
		return v.validateMin(value, rule.Params)
	case TypeMax:
		return v.validateMax(value, rule.Params)
	case TypeMinLength:
		return v.validateMinLength(value, rule.Params)
	case TypeMaxLength:
		return v.validateMaxLength(value, rule.Params)
	case TypePattern:
		return v.validatePattern(value, rule.Params)
	case TypeCustom:
		return v.validateCustom(value, rule.Params)
	case TypeChoices:
		return v.validateChoices(value, rule.Params)
	case TypeDate:
		return v.validateDate(value)
	case TypeDateTime:
		return v.validateDateTime(value)
	default:
		return "Unknown validation type"
	}
}

// validateRequired checks if a value is required and present
func (v *Validator) validateRequired(value interface{}) string {
	if value == nil {
		return "This field is required"
	}
	
	if str, ok := value.(string); ok && strings.TrimSpace(str) == "" {
		return "This field is required"
	}
	
	return ""
}

// validateString checks if a value is a string
func (v *Validator) validateString(value interface{}) string {
	if value == nil {
		return ""
	}
	
	if _, ok := value.(string); !ok {
		return "Must be a string"
	}
	
	return ""
}

// validateEmail checks if a value is a valid email
func (v *Validator) validateEmail(value interface{}) string {
	if value == nil {
		return ""
	}
	
	str, ok := value.(string)
	if !ok {
		return "Please enter a valid email address"
	}
	
	if strings.TrimSpace(str) == "" {
		return ""
	}
	
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(str) {
		return "Please enter a valid email address"
	}
	
	return ""
}

// validatePhone checks if a value is a valid phone number
func (v *Validator) validatePhone(value interface{}) string {
	if value == nil {
		return ""
	}
	
	str, ok := value.(string)
	if !ok {
		return "Please enter a valid phone number"
	}
	
	if strings.TrimSpace(str) == "" {
		return ""
	}
	
	// Remove spaces, dashes, and parentheses
	cleanPhone := regexp.MustCompile(`[\s\-\(\)]+`).ReplaceAllString(str, "")
	phoneRegex := regexp.MustCompile(`^\+?[1-9]\d{9,14}$`)
	
	if !phoneRegex.MatchString(cleanPhone) {
		return "Please enter a valid phone number"
	}
	
	return ""
}

// validateURL checks if a value is a valid URL
func (v *Validator) validateURL(value interface{}) string {
	if value == nil {
		return ""
	}
	
	str, ok := value.(string)
	if !ok {
		return "Please enter a valid URL"
	}
	
	if strings.TrimSpace(str) == "" {
		return ""
	}
	
	urlRegex := regexp.MustCompile(`^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$`)
	if !urlRegex.MatchString(str) {
		return "Please enter a valid URL"
	}
	
	return ""
}

// validateNumber checks if a value is a valid number
func (v *Validator) validateNumber(value interface{}) string {
	if value == nil {
		return ""
	}
	
	if strings.TrimSpace(fmt.Sprintf("%v", value)) == "" {
		return ""
	}
	
	switch value.(type) {
	case int, int8, int16, int32, int64:
		return ""
	case uint, uint8, uint16, uint32, uint64:
		return ""
	case float32, float64:
		return ""
	case string:
		str := value.(string)
		if _, err := strconv.ParseFloat(str, 64); err != nil {
			return "Please enter a valid number"
		}
		return ""
	default:
		return "Please enter a valid number"
	}
}

// validateInteger checks if a value is a valid integer
func (v *Validator) validateInteger(value interface{}) string {
	if value == nil {
		return ""
	}
	
	if strings.TrimSpace(fmt.Sprintf("%v", value)) == "" {
		return ""
	}
	
	switch value.(type) {
	case int, int8, int16, int32, int64:
		return ""
	case uint, uint8, uint16, uint32, uint64:
		return ""
	case string:
		str := value.(string)
		if _, err := strconv.ParseInt(str, 10, 64); err != nil {
			return "Please enter a valid integer"
		}
		return ""
	default:
		return "Please enter a valid integer"
	}
}

// validateMin checks if a value meets the minimum value
func (v *Validator) validateMin(value interface{}, params map[string]interface{}) string {
	if value == nil {
		return ""
	}
	
	minValue, ok := params["value"]
	if !ok {
		return "Minimum value not specified"
	}
	
	var numValue float64
	switch v := value.(type) {
	case int:
		numValue = float64(v)
	case int8:
		numValue = float64(v)
	case int16:
		numValue = float64(v)
	case int32:
		numValue = float64(v)
	case int64:
		numValue = float64(v)
	case uint:
		numValue = float64(v)
	case uint8:
		numValue = float64(v)
	case uint16:
		numValue = float64(v)
	case uint32:
		numValue = float64(v)
	case uint64:
		numValue = float64(v)
	case float32:
		numValue = float64(v)
	case float64:
		numValue = v
	case string:
		if str, err := strconv.ParseFloat(v, 64); err == nil {
			numValue = str
		} else {
			return "Please enter a valid number"
		}
	default:
		return "Please enter a valid number"
	}
	
	var minNum float64
	switch m := minValue.(type) {
	case int:
		minNum = float64(m)
	case int8:
		minNum = float64(m)
	case int16:
		minNum = float64(m)
	case int32:
		minNum = float64(m)
	case int64:
		minNum = float64(m)
	case uint:
		minNum = float64(m)
	case uint8:
		minNum = float64(m)
	case uint16:
		minNum = float64(m)
	case uint32:
		minNum = float64(m)
	case uint64:
		minNum = float64(m)
	case float32:
		minNum = float64(m)
	case float64:
		minNum = m
	default:
		return "Invalid minimum value"
	}
	
	if numValue < minNum {
		return fmt.Sprintf("Value must be at least %v", minValue)
	}
	
	return ""
}

// validateMax checks if a value meets the maximum value
func (v *Validator) validateMax(value interface{}, params map[string]interface{}) string {
	if value == nil {
		return ""
	}
	
	maxValue, ok := params["value"]
	if !ok {
		return "Maximum value not specified"
	}
	
	var numValue float64
	switch v := value.(type) {
	case int:
		numValue = float64(v)
	case int8:
		numValue = float64(v)
	case int16:
		numValue = float64(v)
	case int32:
		numValue = float64(v)
	case int64:
		numValue = float64(v)
	case uint:
		numValue = float64(v)
	case uint8:
		numValue = float64(v)
	case uint16:
		numValue = float64(v)
	case uint32:
		numValue = float64(v)
	case uint64:
		numValue = float64(v)
	case float32:
		numValue = float64(v)
	case float64:
		numValue = v
	case string:
		if str, err := strconv.ParseFloat(v, 64); err == nil {
			numValue = str
		} else {
			return "Please enter a valid number"
		}
	default:
		return "Please enter a valid number"
	}
	
	var maxNum float64
	switch m := maxValue.(type) {
	case int:
		maxNum = float64(m)
	case int8:
		maxNum = float64(m)
	case int16:
		maxNum = float64(m)
	case int32:
		maxNum = float64(m)
	case int64:
		maxNum = float64(m)
	case uint:
		maxNum = float64(m)
	case uint8:
		maxNum = float64(m)
	case uint16:
		maxNum = float64(m)
	case uint32:
		maxNum = float64(m)
	case uint64:
		maxNum = float64(m)
	case float32:
		maxNum = float64(m)
	case float64:
		maxNum = m
	default:
		return "Invalid maximum value"
	}
	
	if numValue > maxNum {
		return fmt.Sprintf("Value must be at most %v", maxValue)
	}
	
	return ""
}

// validateMinLength checks if a string meets the minimum length
func (v *Validator) validateMinLength(value interface{}, params map[string]interface{}) string {
	if value == nil {
		return ""
	}
	
	minLength, ok := params["length"]
	if !ok {
		return "Minimum length not specified"
	}
	
	var length int
	switch v := value.(type) {
	case string:
		length = len(v)
	case []interface{}:
		length = len(v)
	case map[string]interface{}:
		length = len(v)
	default:
		// For other types, convert to string and check length
		length = len(fmt.Sprintf("%v", v))
	}
	
	var minLengthInt int
	switch m := minLength.(type) {
	case int:
		minLengthInt = m
	case int8:
		minLengthInt = int(m)
	case int16:
		minLengthInt = int(m)
	case int32:
		minLengthInt = int(m)
	case int64:
		minLengthInt = int(m)
	case uint:
		minLengthInt = int(m)
	case uint8:
		minLengthInt = int(m)
	case uint16:
		minLengthInt = int(m)
	case uint32:
		minLengthInt = int(m)
	case uint64:
		minLengthInt = int(m)
	default:
		return "Invalid minimum length"
	}
	
	if length < minLengthInt {
		return fmt.Sprintf("Must be at least %v characters", minLength)
	}
	
	return ""
}

// validateMaxLength checks if a string meets the maximum length
func (v *Validator) validateMaxLength(value interface{}, params map[string]interface{}) string {
	if value == nil {
		return ""
	}
	
	maxLength, ok := params["length"]
	if !ok {
		return "Maximum length not specified"
	}
	
	var length int
	switch v := value.(type) {
	case string:
		length = len(v)
	case []interface{}:
		length = len(v)
	case map[string]interface{}:
		length = len(v)
	default:
		// For other types, convert to string and check length
		length = len(fmt.Sprintf("%v", v))
	}
	
	var maxLengthInt int
	switch m := maxLength.(type) {
	case int:
		maxLengthInt = m
	case int8:
		maxLengthInt = int(m)
	case int16:
		maxLengthInt = int(m)
	case int32:
		maxLengthInt = int(m)
	case int64:
		maxLengthInt = int(m)
	case uint:
		maxLengthInt = int(m)
	case uint8:
		maxLengthInt = int(m)
	case uint16:
		maxLengthInt = int(m)
	case uint32:
		maxLengthInt = int(m)
	case uint64:
		maxLengthInt = int(m)
	default:
		return "Invalid maximum length"
	}
	
	if length > maxLengthInt {
		return fmt.Sprintf("Must be at most %v characters", maxLength)
	}
	
	return ""
}

// validatePattern checks if a value matches a pattern
func (v *Validator) validatePattern(value interface{}, params map[string]interface{}) string {
	if value == nil {
		return ""
	}
	
	pattern, ok := params["pattern"]
	if !ok {
		return "Pattern not specified"
	}
	
	str, ok := value.(string)
	if !ok {
		return "Must be a string"
	}
	
	if strings.TrimSpace(str) == "" {
		return ""
	}
	
	patternStr, ok := pattern.(string)
	if !ok {
		return "Invalid pattern"
	}
	
	regex, err := regexp.Compile(patternStr)
	if err != nil {
		return "Invalid pattern"
	}
	
	if !regex.MatchString(str) {
		return "Invalid format"
	}
	
	return ""
}

// validateCustom checks a value using a custom validator
func (v *Validator) validateCustom(value interface{}, params map[string]interface{}) string {
	validatorName, ok := params["validator"]
	if !ok {
		return "Custom validator not specified"
	}
	
	validatorNameStr, ok := validatorName.(string)
	if !ok {
		return "Invalid custom validator name"
	}
	
	validator, exists := v.customValidators[validatorNameStr]
	if !exists {
		return "Custom validator not found"
	}
	
	if !validator(value) {
		return "Invalid input"
	}
	
	return ""
}

// validateChoices checks if a value is one of the allowed choices
func (v *Validator) validateChoices(value interface{}, params map[string]interface{}) string {
	if value == nil {
		return ""
	}
	
	choices, ok := params["choices"]
	if !ok {
		return "Choices not specified"
	}
	
	choicesSlice, ok := choices.([]interface{})
	if !ok {
		return "Invalid choices"
	}
	
	for _, choice := range choicesSlice {
		if reflect.DeepEqual(value, choice) {
			return ""
		}
	}
	
	return fmt.Sprintf("Must be one of: %v", choices)
}

// validateDate checks if a value is a valid date
func (v *Validator) validateDate(value interface{}) string {
	if value == nil {
		return ""
	}
	
	str, ok := value.(string)
	if !ok {
		return "Please enter a valid date"
	}
	
	if strings.TrimSpace(str) == "" {
		return ""
	}
	
	// Try parsing as YYYY-MM-DD
	_, err := time.Parse("2006-01-02", str)
	if err != nil {
		return "Please enter a valid date (YYYY-MM-DD)"
	}
	
	return ""
}

// validateDateTime checks if a value is a valid datetime
func (v *Validator) validateDateTime(value interface{}) string {
	if value == nil {
		return ""
	}
	
	str, ok := value.(string)
	if !ok {
		return "Please enter a valid datetime"
	}
	
	if strings.TrimSpace(str) == "" {
		return ""
	}
	
	// Try parsing as RFC3339
	_, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return "Please enter a valid datetime"
	}
	
	return ""
}

// ValidationRuleBuilder provides a fluent interface for building validation rules
type ValidationRuleBuilder struct {
	rules []*ValidationRule
}

// NewValidationRuleBuilder creates a new validation rule builder
func NewValidationRuleBuilder() *ValidationRuleBuilder {
	return &ValidationRuleBuilder{
		rules: make([]*ValidationRule, 0),
	}
}

// Required adds a required rule
func (b *ValidationRuleBuilder) Required(message ...string) *ValidationRuleBuilder {
	var msg string
	if len(message) > 0 {
		msg = message[0]
	}
	b.rules = append(b.rules, NewValidationRule(TypeRequired, nil, msg))
	return b
}

// Email adds an email rule
func (b *ValidationRuleBuilder) Email(message ...string) *ValidationRuleBuilder {
	var msg string
	if len(message) > 0 {
		msg = message[0]
	}
	b.rules = append(b.rules, NewValidationRule(TypeEmail, nil, msg))
	return b
}

// Phone adds a phone rule
func (b *ValidationRuleBuilder) Phone(message ...string) *ValidationRuleBuilder {
	var msg string
	if len(message) > 0 {
		msg = message[0]
	}
	b.rules = append(b.rules, NewValidationRule(TypePhone, nil, msg))
	return b
}

// URL adds a URL rule
func (b *ValidationRuleBuilder) URL(message ...string) *ValidationRuleBuilder {
	var msg string
	if len(message) > 0 {
		msg = message[0]
	}
	b.rules = append(b.rules, NewValidationRule(TypeURL, nil, msg))
	return b
}

// Number adds a number rule
func (b *ValidationRuleBuilder) Number(message ...string) *ValidationRuleBuilder {
	var msg string
	if len(message) > 0 {
		msg = message[0]
	}
	b.rules = append(b.rules, NewValidationRule(TypeNumber, nil, msg))
	return b
}

// Integer adds an integer rule
func (b *ValidationRuleBuilder) Integer(message ...string) *ValidationRuleBuilder {
	var msg string
	if len(message) > 0 {
		msg = message[0]
	}
	b.rules = append(b.rules, NewValidationRule(TypeInteger, nil, msg))
	return b
}

// Min adds a minimum value rule
func (b *ValidationRuleBuilder) Min(value interface{}, message ...string) *ValidationRuleBuilder {
	var msg string
	if len(message) > 0 {
		msg = message[0]
	}
	params := map[string]interface{}{"value": value}
	b.rules = append(b.rules, NewValidationRule(TypeMin, params, msg))
	return b
}

// Max adds a maximum value rule
func (b *ValidationRuleBuilder) Max(value interface{}, message ...string) *ValidationRuleBuilder {
	var msg string
	if len(message) > 0 {
		msg = message[0]
	}
	params := map[string]interface{}{"value": value}
	b.rules = append(b.rules, NewValidationRule(TypeMax, params, msg))
	return b
}

// MinLength adds a minimum length rule
func (b *ValidationRuleBuilder) MinLength(length int, message ...string) *ValidationRuleBuilder {
	var msg string
	if len(message) > 0 {
		msg = message[0]
	}
	params := map[string]interface{}{"length": length}
	b.rules = append(b.rules, NewValidationRule(TypeMinLength, params, msg))
	return b
}

// MaxLength adds a maximum length rule
func (b *ValidationRuleBuilder) MaxLength(length int, message ...string) *ValidationRuleBuilder {
	var msg string
	if len(message) > 0 {
		msg = message[0]
	}
	params := map[string]interface{}{"length": length}
	b.rules = append(b.rules, NewValidationRule(TypeMaxLength, params, msg))
	return b
}

// Pattern adds a pattern rule
func (b *ValidationRuleBuilder) Pattern(pattern string, message ...string) *ValidationRuleBuilder {
	var msg string
	if len(message) > 0 {
		msg = message[0]
	}
	params := map[string]interface{}{"pattern": pattern}
	b.rules = append(b.rules, NewValidationRule(TypePattern, params, msg))
	return b
}

// Choices adds a choices rule
func (b *ValidationRuleBuilder) Choices(choices []interface{}, message ...string) *ValidationRuleBuilder {
	var msg string
	if len(message) > 0 {
		msg = message[0]
	}
	params := map[string]interface{}{"choices": choices}
	b.rules = append(b.rules, NewValidationRule(TypeChoices, params, msg))
	return b
}

// Custom adds a custom rule
func (b *ValidationRuleBuilder) Custom(validatorName string, message ...string) *ValidationRuleBuilder {
	var msg string
	if len(message) > 0 {
		msg = message[0]
	}
	params := map[string]interface{}{"validator": validatorName}
	b.rules = append(b.rules, NewValidationRule(TypeCustom, params, msg))
	return b
}

// Build returns the built rules
func (b *ValidationRuleBuilder) Build() []*ValidationRule {
	return b.rules
}

// Predefined validators
var FormValidators = struct {
	Email       func() *Validator
	Password    func() *Validator
	UserRegistration func() *Validator
	ContactForm func() *Validator
}{
	Email: func() *Validator {
		validator := NewValidator()
		validator.AddRules("email", []*ValidationRule{
			NewValidationRule(TypeRequired, nil, ""),
			NewValidationRule(TypeEmail, nil, ""),
		})
		return validator
	},
	
	Password: func() *Validator {
		validator := NewValidator()
		validator.AddRules("password", []*ValidationRule{
			NewValidationRule(TypeRequired, nil, ""),
			NewValidationRule(TypeMinLength, map[string]interface{}{"length": 8}, ""),
			NewValidationRule(TypePattern, map[string]interface{}{"pattern": "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)"}, "Password must contain at least one lowercase letter, one uppercase letter, and one number"),
		})
		return validator
	},
	
	UserRegistration: func() *Validator {
		validator := NewValidator()
		
		validator.AddRules("username", []*ValidationRule{
			NewValidationRule(TypeRequired, nil, ""),
			NewValidationRule(TypeMinLength, map[string]interface{}{"length": 3}, ""),
			NewValidationRule(TypeMaxLength, map[string]interface{}{"length": 50}, ""),
			NewValidationRule(TypePattern, map[string]interface{}{"pattern": "^[a-zA-Z0-9_]+$"}, "Username can only contain letters, numbers, and underscores"),
		})
		
		validator.AddRules("email", []*ValidationRule{
			NewValidationRule(TypeRequired, nil, ""),
			NewValidationRule(TypeEmail, nil, ""),
		})
		
		validator.AddRules("password", []*ValidationRule{
			NewValidationRule(TypeRequired, nil, ""),
			NewValidationRule(TypeMinLength, map[string]interface{}{"length": 8}, ""),
			NewValidationRule(TypePattern, map[string]interface{}{"pattern": "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)"}, "Password must contain at least one lowercase letter, one uppercase letter, and one number"),
		})
		
		validator.AddRules("confirmPassword", []*ValidationRule{
			NewValidationRule(TypeRequired, nil, ""),
		})
		
		validator.AddCustomValidator("passwords_match", func(value interface{}) bool {
			// This would need to be implemented with access to both password and confirmPassword
			return true
		})
		
		validator.AddRules("age", []*ValidationRule{
			NewValidationRule(TypeMin, map[string]interface{}{"value": 0}, ""),
			NewValidationRule(TypeMax, map[string]interface{}{"value": 150}, ""),
		})
		
		return validator
	},
	
	ContactForm: func() *Validator {
		validator := NewValidator()
		
		validator.AddRules("name", []*ValidationRule{
			NewValidationRule(TypeRequired, nil, ""),
			NewValidationRule(TypeMinLength, map[string]interface{}{"length": 2}, ""),
		})
		
		validator.AddRules("email", []*ValidationRule{
			NewValidationRule(TypeRequired, nil, ""),
			NewValidationRule(TypeEmail, nil, ""),
		})
		
		validator.AddRules("phone", []*ValidationRule{
			NewValidationRule(TypePhone, nil, ""),
		})
		
		validator.AddRules("message", []*ValidationRule{
			NewValidationRule(TypeRequired, nil, ""),
			NewValidationRule(TypeMinLength, map[string]interface{}{"length": 10}, ""),
			NewValidationRule(TypeMaxLength, map[string]interface{}{"length": 1000}, ""),
		})
		
		return validator
	},
}

// Validation utilities
var ValidationUtils = struct {
	ValidateEmailList func([]string) []string
	SanitizeString   func(string, map[string]bool) string
	ValidatePasswordStrength func(string) PasswordStrengthResult
	GenerateSchemaFromModel func(interface{}, map[string]FieldConfig) map[string][]*ValidationRule
}{
	ValidateEmailList: func(emails []string) []string {
		var invalidEmails []string
		validator := NewValidator()
		
		for _, email := range emails {
			if err := validator.validateEmail(email); err != "" {
				invalidEmails = append(invalidEmails, email)
			}
		}
		
		return invalidEmails
	},
	
	SanitizeString: func(value string, options map[string]bool) string {
		allowSpaces := options["allow_spaces"]
		allowSpecial := options["allow_special"]
		maxLength := options["max_length"]
		
		var pattern *regexp.Regexp
		if allowSpaces && allowSpecial {
			pattern = regexp.MustCompile(`[^a-zA-Z0-9\s\-\._@+]`)
		} else if allowSpaces {
			pattern = regexp.MustCompile(`[^a-zA-Z0-9\s]`)
		} else if allowSpecial {
			pattern = regexp.MustCompile(`[^a-zA-Z0-9\-\._@+]`)
		} else {
			pattern = regexp.MustCompile(`[^a-zA-Z0-9]`)
		}
		
		sanitized := pattern.ReplaceAllString(value, "")
		
		if maxLength {
			if maxLen, ok := options["max_length_value"].(int); ok && len(sanitized) > maxLen {
				sanitized = sanitized[:maxLen]
			}
		}
		
		return sanitized
	},
	
	ValidatePasswordStrength: func(password string) PasswordStrengthResult {
		result := PasswordStrengthResult{
			IsValid:    true,
			Score:      0,
			Issues:     make([]string, 0),
			Suggestions: make([]string, 0),
		}
		
		if len(password) < 8 {
			result.IsValid = false
			result.Issues = append(result.Issues, "Password must be at least 8 characters")
		} else {
			result.Score++
		}
		
		if !regexp.MustCompile(`[a-z]`).MatchString(password) {
			result.IsValid = false
			result.Issues = append(result.Issues, "Password must contain lowercase letters")
		} else {
			result.Score++
		}
		
		if !regexp.MustCompile(`[A-Z]`).MatchString(password) {
			result.IsValid = false
			result.Issues = append(result.Issues, "Password must contain uppercase letters")
		} else {
			result.Score++
		}
		
		if !regexp.MustCompile(`\d`).MatchString(password) {
			result.IsValid = false
			result.Issues = append(result.Issues, "Password must contain numbers")
		} else {
			result.Score++
		}
		
		if !regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password) {
			result.Suggestions = append(result.Suggestions, "Consider adding special characters for stronger security")
		} else {
			result.Score++
		}
		
		// Check for common patterns
		if regexp.MustCompile(`^(.)\1+$`).MatchString(password) {
			result.Issues = append(result.Issues, "Password cannot be repeated characters")
			result.IsValid = false
		}
		
		if regexp.MustCompile(`(?i)password|123456|qwerty`).MatchString(password) {
			result.Issues = append(result.Issues, "Password is too common")
			result.IsValid = false
		}
		
		return result
	},
	
	GenerateSchemaFromModel: func(model interface{}, fieldConfigs map[string]FieldConfig) map[string][]*ValidationRule {
		schema := make(map[string][]*ValidationRule)
		
		for fieldName, config := range fieldConfigs {
			var rules []*ValidationRule
			
			// Add required rule if specified
			if config.Required {
				rules = append(rules, NewValidationRule(TypeRequired, nil, ""))
			}
			
			// Add type-specific rules
			switch config.Type {
			case "email":
				rules = append(rules, NewValidationRule(TypeEmail, nil, ""))
			case "phone":
				rules = append(rules, NewValidationRule(TypePhone, nil, ""))
			case "url":
				rules = append(rules, NewValidationRule(TypeURL, nil, ""))
			case "number":
				rules = append(rules, NewValidationRule(TypeNumber, nil, ""))
			case "integer":
				rules = append(rules, NewValidationRule(TypeInteger, nil, ""))
			}
			
			// Add length constraints
			if config.MinLength != nil {
				rules = append(rules, NewValidationRule(TypeMinLength, map[string]interface{}{"length": config.MinLength}, ""))
			}
			
			if config.MaxLength != nil {
				rules = append(rules, NewValidationRule(TypeMaxLength, map[string]interface{}{"length": config.MaxLength}, ""))
			}
			
			// Add value constraints
			if config.Min != nil {
				rules = append(rules, NewValidationRule(TypeMin, map[string]interface{}{"value": config.Min}, ""))
			}
			
			if config.Max != nil {
				rules = append(rules, NewValidationRule(TypeMax, map[string]interface{}{"value": config.Max}, ""))
			}
			
			// Add pattern
			if config.Pattern != "" {
				rules = append(rules, NewValidationRule(TypePattern, map[string]interface{}{"pattern": config.Pattern}, ""))
			}
			
			// Add choices
			if len(config.Choices) > 0 {
				choices := make([]interface{}, len(config.Choices))
				for i, choice := range config.Choices {
					choices[i] = choice
				}
				rules = append(rules, NewValidationRule(TypeChoices, map[string]interface{}{"choices": choices}, ""))
			}
			
			if len(rules) > 0 {
				schema[fieldName] = rules
			}
		}
		
		return schema
	},
}

// PasswordStrengthResult represents password strength validation result
type PasswordStrengthResult struct {
	IsValid     bool     `json:"is_valid"`
	Score       int      `json:"score"`
	Issues      []string `json:"issues"`
	Suggestions []string `json:"suggestions"`
}

// FieldConfig represents field configuration for schema generation
type FieldConfig struct {
	Required   bool          `json:"required"`
	Type       string        `json:"type"`
	MinLength  *int          `json:"min_length,omitempty"`
	MaxLength  *int          `json:"max_length,omitempty"`
	Min        interface{}   `json:"min,omitempty"`
	Max        interface{}   `json:"max,omitempty"`
	Pattern    string        `json:"pattern,omitempty"`
	Choices    []string      `json:"choices,omitempty"`
}

// Example usage demonstrates how to use the validation utilities
func ExampleUsage() {
	// Create validator using builder
	validator := NewValidator()
	
	// Add validation rules using builder
	emailRules := NewValidationRuleBuilder().
		Required("Email is required").
		Email("Please enter a valid email").
		Build()
	
	validator.AddRules("email", emailRules)
	
	passwordRules := NewValidationRuleBuilder().
		Required("Password is required").
		MinLength(8, "Password must be at least 8 characters").
		Pattern("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)", "Password must contain at least one lowercase letter, one uppercase letter, and one number").
		Build()
	
	validator.AddRules("password", passwordRules)
	
	// Test field validation
	emailResult := validator.ValidateField("email", "test@example.com")
	fmt.Printf("Email validation: %v, Errors: %v\n", emailResult.IsValid, emailResult.Errors)
	
	// Test form validation
	formData := map[string]interface{}{
		"email":    "invalid-email",
		"password": "weak",
	}
	
	formResult := validator.Validate(formData)
	fmt.Printf("Form validation: %v\n", formResult.IsValid)
	fmt.Printf("All errors: %v\n", formResult.GetAllErrors())
	
	// Use predefined validators
	userValidator := FormValidators.UserRegistration()
	userResult := userValidator.Validate(map[string]interface{}{
		"username": "testuser",
		"email":    "test@example.com",
		"password": "Password123",
	})
	
	fmt.Printf("User registration validation: %v\n", userResult.IsValid)
	
	// Test password strength
	passwordStrength := ValidationUtils.ValidatePasswordStrength("MyPassword123!")
	fmt.Printf("Password strength: %+v\n", passwordStrength)
	
	// Test email list validation
	invalidEmails := ValidationUtils.ValidateEmailList([]string{
		"valid@example.com",
		"invalid-email",
		"another@example.com",
	})
	fmt.Printf("Invalid emails: %v\n", invalidEmails)
	
	// Test string sanitization
	sanitized := ValidationUtils.SanitizeString("Hello World! @#$", map[string]bool{
		"allow_spaces": true,
		"allow_special": true,
	})
	fmt.Printf("Sanitized string: %s\n", sanitized)
}
