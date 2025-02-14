package logger

import (
	"time"
	//"github.com/jacobshu/chirpy/internal/types"
	"fmt"
	"log/slog"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cast"
)

type Log struct {
	Time    time.Time
	Data    any
	Message string
	Level   slog.Level
}

type Logger struct {
	Colors LogColors
}

type LogColors struct {
	Base  color.Color
	Debug color.Color
	Info  color.Color
	Warn  color.Color
	Error color.Color
}

var printLog = func(log *Log) {
	var str strings.Builder
	baseC := color.New(color.FgWhite)
	debugC := color.New(color.Bold, color.FgHiBlack)
	infoC := color.New(color.Bold, color.FgWhite)
	warnC := color.New(color.Bold, color.FgYellow)
	warnText := color.New(color.FgYellow)
	errorC := color.New(color.Bold, color.FgRed)
	errorText := color.New(color.FgRed)
	defaultC := color.New(color.Bold, color.FgCyan)
	defaultText := color.New(color.FgCyan)

	switch log.Level {
	case slog.LevelDebug:
		str.WriteString(debugC.Sprint("DEBUG "))
		str.WriteString(baseC.Sprint(log.Message))
	case slog.LevelInfo:
		str.WriteString(infoC.Sprint("INFO "))
		str.WriteString(baseC.Sprint(log.Message))
	case slog.LevelWarn:
		str.WriteString(warnC.Sprint("WARN "))
		str.WriteString(warnText.Sprint(log.Message))
	case slog.LevelError:
		str.WriteString(errorC.Sprint("ERROR "))
		str.WriteString(errorText.Sprint(log.Message))
	default:
		str.WriteString(defaultC.Sprintf("[%d] ", log.Level))
		str.WriteString(defaultText.Sprint(log.Message))
	}

	str.WriteString("\n")

	fmt.Print(str.String())
}
