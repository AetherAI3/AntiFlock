//go:build !linux

package main

import (
	"context"
	"errors"
	"io"

	"github.com/DBarr3/AntiFlock/agent/collectors"
)

func captureRotation(context.Context, string, string, string, collectors.RotationEnrollment, io.Writer) error {
	return errors.New("capture-rotation requires Linux")
}
