package ja4go

import "strconv"

type BuildJA4TInput struct {
	PacketNum int

	// tcp.window_size_value.
	WindowSize uint16

	// tcp.option_kind.
	Options []uint8

	// MSS изtcp.options.mss_val
	MSS *uint16

	// Window scale из tcp.options.wscale.shift
	WindowScale *uint8
}

/// Format:
///   <window size>_<options>_<mss>_<window scale>
///
/// Example:
///   64240_2-1-3-1-1-4_1460_8
func BuildJA4T(in BuildJA4TInput) string {
	win := strconv.Itoa(int(in.WindowSize))

	// Опции
	opts := ""
	for i, k := range in.Options {
		if i > 0 {
			opts += "-"
		}
		opts += strconv.Itoa(int(k))
	}

	// MSS
	mss := "0"
	if in.MSS != nil {
		mss = strconv.Itoa(int(*in.MSS))
	}

	// Window scale
	ws := "0"
	if in.WindowScale != nil {
		ws = strconv.Itoa(int(*in.WindowScale))
	}

	return win + "_" + opts + "_" + mss + "_" + ws
}
