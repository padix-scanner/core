package terminal

const (
	Reset = "\033[0m"

	Bold = "\033[1m"
	Dim  = "\033[2m"

	Black   = "\033[30m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"

	BrightRed     = "\033[91m"
	BrightGreen   = "\033[92m"
	BrightYellow  = "\033[93m"
	BrightBlue    = "\033[94m"
	BrightMagenta = "\033[95m"
	BrightCyan    = "\033[96m"
	BrightWhite   = "\033[97m"
)

func Color(color, value string) string {
	return color + value + Reset
}

func RedText(value string) string {
	return Color(Red, value)
}

func GreenText(value string) string {
	return Color(Green, value)
}

func YellowText(value string) string {
	return Color(Yellow, value)
}

func CyanText(value string) string {
	return Color(Cyan, value)
}

func BlueText(value string) string {
	return Color(Blue, value)
}

func BoldText(value string) string {
	return Color(Bold, value)
}

func Success(value string) string {
	return GreenText("[SUCCESS]") + " " + value
}

func Error(value string) string {
	return RedText("[ERROR]") + " " + value
}

func Info(value string) string {
	return CyanText("[INFO]") + " " + value
}

func Warning(value string) string {
	return YellowText("[WARNING]") + " " + value
}
