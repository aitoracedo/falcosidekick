// SPDX-License-Identifier: MIT OR Apache-2.0

package utils

import (
	"fmt"
	"log"
	"runtime"
	"time"
)

const (
	InfoLvl       string = "info"
	InfoPrefix    string = "[INFO] "
	ErrorLvl      string = "error"
	ErrorPrefix   string = "[ERROR]"
	DebugLvl      string = "debug"
	DebugPrefix   string = "[DEBUG]"
	WarningLvl    string = "warning"
	WarningPrefix string = "[WARN] "
	FatalLvl      string = "fatal"
	FatalPrefix   string = "[FATAL]"
)

// EnableTimeTracks controls whether TimeTrack prints timing output.
// Set this to true at startup when the TimeTracks config option is enabled.
var EnableTimeTracks bool

// TimeTrack prints the elapsed time since start together with the name of the
// calling function. It is a no-op unless EnableTimeTracks is true.
// Use it with defer to time any function automatically:
//
//	func MyFunc() {
//	    defer utils.TimeTrack(time.Now())
//	    // ...
//	}
func TimeTrack(start time.Time) {
	if !EnableTimeTracks {
		return
	}
	pc, _, _, ok := runtime.Caller(1)
	name := "unknown"
	if ok {
		name = runtime.FuncForPC(pc).Name()
	}
	fmt.Printf("[TIMER] %s took %s\n", name, time.Since(start))
}

func Log(level, output, msg string) {
	var prefix string
	switch level {
	case InfoLvl:
		prefix = InfoPrefix
	case ErrorLvl:
		prefix = ErrorPrefix
	case DebugLvl:
		prefix = DebugPrefix
	case WarningLvl:
		prefix = WarningPrefix
	}
	if output != "" {
		log.Printf("%v : %v - %v", prefix, output, msg)
	} else {
		log.Printf("%v : %v", prefix, msg)
	}
}
