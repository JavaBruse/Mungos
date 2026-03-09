package logger

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"time"
)

type Level int

const (
	levelDebug Level = iota
	levelInfo
	levelWarn
	levelError
)

var std = &Logger{
	Logger: log.New(os.Stdout, "", 0),
	level:  levelInfo,
}

type Logger struct {
	*log.Logger
	level Level
}

func SetLevel(level Level) { std.level = level }

func (l *Logger) output(level Level, calldepth int, format string, v ...interface{}) {
	if level < l.level {
		return
	}
	_, file, line, _ := runtime.Caller(calldepth)
	short := file
	for i := len(file) - 1; i > 0; i-- {
		if file[i] == '/' {
			short = file[i+1:]
			break
		}
	}
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	levelStr := map[Level]string{
		levelDebug: "DEBUG",
		levelInfo:  "INFO",
		levelWarn:  "WARN",
		levelError: "ERROR",
	}[level]
	l.Printf("%s %s [%s:%d] %s", timestamp, levelStr, short, line, fmt.Sprintf(format, v...))
}

func Debug(format string, v ...interface{}) { std.output(levelDebug, 2, format, v...) }
func Info(format string, v ...interface{})  { std.output(levelInfo, 2, format, v...) }
func Warn(format string, v ...interface{})  { std.output(levelWarn, 2, format, v...) }
func Error(format string, v ...interface{}) { std.output(levelError, 2, format, v...) }
