module [[.ProjectName]]

go 1.21

require (
	github.com/sirupsen/logrus v1.9.3
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	github.com/stretchr/testify v1.8.4
)

// This template documents the dependencies used in Go foundational templates:
// - logrus: Used in logging-utilities.tpl.go for structured logging
// - lumberjack: Used in logging-utilities.tpl.go for log rotation
// - testify: Used in testing-utilities.tpl.go for testing assertions and mocks
//
// Note: These dependencies are optional and can be replaced with standard library
// equivalents if preferred. The templates are designed to work with or without
// these external dependencies.
