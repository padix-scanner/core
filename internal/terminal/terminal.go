package terminal

import (
	"fmt"
	"io"
	"os"
)

// ColoredPrintln prints a colored line.
func ColoredPrintln(color string, values ...any) {
	ColoredFprintln(os.Stdout, color, values...)
}

// ColoredPrintf prints formatted colored text.
func ColoredPrintf(color string, format string, values ...any) {
	ColoredFprintf(os.Stdout, color, format, values...)
}

// ColoredFprintln prints a colored line to a writer.
func ColoredFprintln(w io.Writer, color string, values ...any) {
	fmt.Fprint(w, color)
	fmt.Fprintln(w, values...)
	fmt.Fprint(w, Reset)
}

// ColoredFprintf prints formatted colored text to a writer.
func ColoredFprintf(w io.Writer, color string, format string, values ...any) {
	fmt.Fprint(w, color)
	fmt.Fprintf(w, format, values...)
	fmt.Fprint(w, Reset)
}

func ColoredError(values ...any) {
	w := os.Stderr
	fmt.Fprint(w, RedText(BoldText("[Error] ")))
	fmt.Fprint(w, Red)
	fmt.Fprintln(w, values...)
	fmt.Fprint(w, Reset)
}

func ColoredInfo(values ...any) {
	w := os.Stderr
	fmt.Fprint(w, CyanText(BoldText("[Info] ")))
	fmt.Fprint(w, Cyan)
	fmt.Fprintln(w, values...)
	fmt.Fprint(w, Reset)
}
